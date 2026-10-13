#define _POSIX_C_SOURCE 200809L
/* Standalone measurement only. No network, qdisc, hardware or firmware writes.
 * stdin: CLOCK <id> | ARM <id> <absolute-monotonic-start-ns> <duration-ns>
 *        QUIT
 * stdout: JSON line events; raw /proc snapshots go to the exclusive file.
 * ARM is accepted once; all timing is target-local. SIGTERM/SIGINT cancels.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define STAT_CAPACITY (1024U * 1024U)
#define SECOND_NS UINT64_C(1000000000)
static volatile sig_atomic_t cancelled;

struct boundary {
    uint64_t requested;
    uint64_t before;
    uint64_t after;
    off_t offset;
};

static void stop_requested(int signal_number)
{
    cancelled = signal_number;
}

static uint64_t monotonic_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t)value.tv_sec * SECOND_NS + (uint64_t)value.tv_nsec;
}

static int read_file(const char *path, char *buffer, size_t capacity)
{
    int file = open(path, O_RDONLY | O_CLOEXEC);
    size_t used = 0;
    if (file < 0)
        return -1;
    for (;;) {
        ssize_t count = read(file, buffer + used, capacity - 1 - used);
        if (count < 0 && errno == EINTR && !cancelled)
            continue;
        if (count < 0) {
            close(file);
            return -1;
        }
        if (!count)
            break;
        used += (size_t)count;
        if (used == capacity - 1) {
            close(file);
            errno = EOVERFLOW;
            return -1;
        }
    }
    close(file);
    buffer[used] = '\0';
    return (int)used;
}

static int write_all(int file, const char *data, size_t length)
{
    while (length) {
        ssize_t count = write(file, data, length);
        if (count < 0 && errno == EINTR && !cancelled)
            continue;
        if (count <= 0)
            return -1;
        data += count;
        length -= (size_t)count;
    }
    return 0;
}

static int sample(int output, unsigned int number, uint64_t deadline,
                  char *stat_buffer, struct boundary *boundary)
{
    struct timespec target = {
        .tv_sec = (time_t)(deadline / SECOND_NS),
        .tv_nsec = (long)(deadline % SECOND_NS),
    };
    char uptime_before[128], uptime_after[128], header[64];
    int result, stat_length, before_length, after_length, header_length;
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL);
    } while (result == EINTR && !cancelled);
    if (result || cancelled) {
        errno = result ? result : EINTR;
        return -1;
    }
    boundary->requested = deadline;
    before_length = read_file("/proc/uptime", uptime_before, sizeof(uptime_before));
    boundary->before = monotonic_ns();
    stat_length = read_file("/proc/stat", stat_buffer, STAT_CAPACITY);
    boundary->after = monotonic_ns();
    after_length = read_file("/proc/uptime", uptime_after, sizeof(uptime_after));
    if (before_length < 0 || stat_length < 0 || after_length < 0)
        return -1;
    boundary->offset = lseek(output, 0, SEEK_CUR);
    if (boundary->offset < 0)
        return -1;
    header_length = snprintf(header, sizeof(header), "SAMPLE %u\n", number);
    if (write_all(output, header, (size_t)header_length) ||
        write_all(output, uptime_before, (size_t)before_length) ||
        write_all(output, stat_buffer, (size_t)stat_length) ||
        write_all(output, uptime_after, (size_t)after_length))
        return -1;
    return 0;
}

static void report_boundary(unsigned int number, const struct boundary *value)
{
    printf("{\"event\":\"snapshot\",\"number\":%u,\"requested_ns\":%" PRIu64
           ",\"stat_before_ns\":%" PRIu64 ",\"stat_after_ns\":%" PRIu64
           ",\"raw_offset\":%jd}\n", number, value->requested,
           value->before, value->after, (intmax_t)value->offset);
}

int main(int argc, char **argv)
{
    char boot[128], line[256], extra, command[16];
    struct sigaction action = { .sa_handler = stop_requested };
    struct boundary boundaries[2];
    char *stat_buffer;
    uint64_t identifier, start, duration, now;
    bool armed = false;
    int output, status = 1;
    if (argc != 5 || strcmp(argv[1], "--output") || strcmp(argv[3], "--boot")) {
        fprintf(stderr, "usage: qdx-uniform-cpu --output NEW_FILE --boot EXPECTED_UUID\n");
        return 2;
    }
    if (read_file("/proc/sys/kernel/random/boot_id", boot, sizeof(boot)) < 0)
        return 1;
    boot[strcspn(boot, "\r\n")] = '\0';
    if (strcmp(boot, argv[4])) {
        fprintf(stderr, "actual boot differs from expected boot\n");
        return 2;
    }
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL) || sigaction(SIGALRM, &action, NULL))
        return 1;
    alarm(180); /* Safety bound owns only this sampler, never the measured path. */
    stat_buffer = malloc(STAT_CAPACITY);
    if (!stat_buffer)
        return 1;
    output = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output < 0) {
        perror("exclusive sample output");
        free(stat_buffer);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"event\":\"ready\",\"schema_version\":1,\"pid\":%ld,\"boot\":\"%s\",\"monotonic_ns\":%" PRIu64 ",\"target_user_hz\":%ld}\n",
           (long)getpid(), boot, monotonic_ns(), sysconf(_SC_CLK_TCK));
    while (!cancelled && fgets(line, sizeof(line), stdin)) {
        int fields = sscanf(line, "%15s %" SCNu64 " %" SCNu64 " %" SCNu64 " %c",
                            command, &identifier, &start, &duration, &extra);
        if (!strcmp(line, "QUIT\n") || !strcmp(line, "QUIT")) {
            status = 0;
            break;
        }
        if (fields == 2 && !strcmp(command, "CLOCK")) {
            uint64_t stamp = monotonic_ns();
            printf("{\"event\":\"clock\",\"id\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 "}\n", identifier, stamp);
            continue;
        }
        now = monotonic_ns();
        if (fields != 4 || strcmp(command, "ARM") || armed ||
            duration == 0 || duration > 120 * SECOND_NS ||
            start < now || start - now > 30 * SECOND_NS ||
            start > UINT64_MAX - duration) {
            fprintf(stderr, "invalid, repeated or late command\n");
            break;
        }
        armed = true;
        printf("{\"event\":\"armed\",\"id\":%" PRIu64 ",\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 "}\n",
               identifier, start, start + duration);
        if (sample(output, 0, start, stat_buffer, &boundaries[0]) ||
            sample(output, 1, start + duration, stat_buffer, &boundaries[1])) {
            perror("sample");
            break;
        }
        /* Emit only after both local reads; SSH backpressure cannot shift them. */
        report_boundary(0, &boundaries[0]);
        report_boundary(1, &boundaries[1]);
        printf("{\"event\":\"complete\",\"id\":%" PRIu64 "}\n", identifier);
    }
    if (cancelled)
        fprintf(stderr, "sampler cancelled by signal %d; raw partial evidence retained\n", cancelled);
    if (close(output))
        status = 1;
    free(stat_buffer);
    printf("{\"event\":\"exit\",\"status\":%d,\"armed\":%s,\"signal\":%d}\n",
           status, armed ? "true" : "false", cancelled);
    return status;
}
