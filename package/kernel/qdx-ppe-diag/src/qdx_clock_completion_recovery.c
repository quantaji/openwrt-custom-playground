// SPDX-License-Identifier: GPL-2.0-only
/* Only recover consumed completion events of recorded clock probe r3.
 * Original ELF2264c9fc, build-idb4bc5604. No arbitrary address or payload API.
 */
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx_diag_clock.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/swait.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>

/* Exact observed original layouts, checked against its frozen ELF/DWARF. */
struct clock_endpoint {
 struct qdx_endpoint *endpoint;
 struct qdx_receiver *receiver;
 struct qdx_packet_op *operation;
 struct qdx_request *request;
 struct qdx_result result;
 u32 ifnum, opcode, active, unexpected;
 bool configured, next, enabled, disabled, retired;
};
struct clock_row {
 struct qdx_diag_clock_sample sample;
 struct completion clone_done;
 u64 begin_ns, submit_end_ns, end_ns, clone_ns;
 u32 clone_words[6], clones, clone_ifnum, clone_type, clone_length, clone_mod4;
 u32 endpoint, pair;
 bool submitted, clone_valid, checked, probe;
};
struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(spinlock_t) == 4);
static_assert(sizeof(struct completion) == 32);
static_assert(sizeof(struct qdx_diag_clock_sample) == 112);
static_assert(sizeof(struct clock_endpoint) == 112);
static_assert(sizeof(struct clock_row) == 232);
static_assert(offsetof(struct clock_row, clone_done) == 112);
static_assert(offsetof(struct clock_row, begin_ns) == 144);
static bool allow_writes;
module_param(allow_writes, bool, 0400);
static DEFINE_MUTEX(recovery_lock);
static struct dentry *directory;
static bool recovered;
static u32 samples_signaled, clones_signaled;
static int result;
static unsigned long observed_text, observed_data, observed_bss;
static const u8 expected_build_id[20] = {
 0xb4,0xbc,0x56,0x04,0xb2,0xbb,0x51,0xa2,0xda,0xbd,
 0xf9,0x6f,0x00,0xc3,0xbc,0x43,0xff,0xf2,0x6c,0xa3
};

static unsigned long recovery_section(struct module *module, const char *name)
{
 struct recovery_sections *sections = (void *)module->sect_attrs;
 const struct bin_attribute *const *entry;
 unsigned int i;

 if (!sections || !sections->grp.bin_attrs) return 0;
 entry = sections->grp.bin_attrs;
 for (i = 0; i < 64 && entry[i]; i++)
  if (!strcmp(entry[i]->attr.name, name)) return (unsigned long)entry[i]->private;
 return 0;
}

static int recovery_run(void)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe anchor = { .symbol_name = "qdx_clock_diag:clock_control_write" };
 struct module *(*find_named)(const char *);
 struct module *module;
 struct mutex *lock;
 spinlock_t *clone_lock;
 struct clock_endpoint *ep;
 struct clock_row *rows, *row;
 struct qdx_diag_clock_sample *sample;
 unsigned long text, data, bss, note, flags;
 u64 first, last, lifted;
 unsigned int i;
 int error;

 if (recovered) return -EALREADY;
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr;
 unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_clock_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_clock_diag")) {
  error = -ESTALE; goto put;
 }
 text = recovery_section(module, ".text");
 data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss");
 note = recovery_section(module, ".note.gnu.build-id");
 if (text != 0xffffffc079b9a200UL || data != 0xffffffc079e84010UL ||
     bss != 0xffffffc079e84030UL || !note ||
     recovery_section(module, ".gnu.linkonce.this_module") != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x13eb, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0x1f, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x581f, module, MOD_DATA) ||
     !within_module(note, module) || !within_module(note + 35, module)) {
  error = -ERANGE; goto put;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), expected_build_id, sizeof(expected_build_id))) {
  error = -ESTALE; goto put;
 }
 error = register_kprobe(&anchor);
 if (error) goto put;
 error = (unsigned long)anchor.addr == text + 0xba8 ? 0 : -ESTALE;
 unregister_kprobe(&anchor);
 if (error) goto put;
 observed_text = text; observed_data = data; observed_bss = bss;
 lock = (void *)data;
 clone_lock = (void *)(bss + 0x118);
 ep = (void *)(bss + 0x18);
 rows = (void *)(bss + 0x120);
 mutex_lock(lock);
 /* Normal restore already closed both publishers. This pass only repairs
  * the completion counters consumed by earlier successful waits.
  */
 if (!*(bool *)bss || !*(bool *)(bss + 0x105) || !*(bool *)(bss + 0x106) ||
     !*(bool *)(bss + 0x107) || *(bool *)(bss + 0x104) ||
     *(u32 *)(bss + 0x100) != 24 || *(u32 *)(bss + 0x10c) != 8 ||
     *(u32 *)(bss + 0x110) != 8 || *(u32 *)(bss + 0x114) != 8 ||
     *(int *)(bss + 0x108) != -EINPROGRESS) {
  error = -EPERM; goto unlock;
 }
 for (i = 0; i < 2; i++) {
  if (!ep[i].endpoint || !ep[i].receiver || !ep[i].operation || ep[i].request ||
      !ep[i].configured || ep[i].retired || ep[i].ifnum != 30 + i ||
      ep[i].active != U32_MAX || ep[i].unexpected ||
      ep[i].enabled != !i || ep[i].disabled != !!i || ep[i].next != !i ||
      !qdx_packet_op_drained(ep[i].operation)) {
   error = -EBUSY; goto unlock;
  }
 }
 synchronize_net();
 spin_lock_irqsave(clone_lock, flags);
 if (ep[0].active != U32_MAX || ep[1].active != U32_MAX || ep[0].unexpected || ep[1].unexpected ||
     rows[0].begin_ns != 379035798397ULL || rows[23].end_ns != 379063649959ULL) {
  error = -ESTALE; goto spin_unlock;
 }
 for (i = 0; i < 24; i++) {
  row = &rows[i]; sample = &row->sample;
  if (!row->submitted || !row->checked || !row->probe || row->pair != i / 3 ||
      row->endpoint != (i % 3 == 1) || sample->error || completion_done(&sample->done) ||
      swait_active(&sample->done.wait) || swait_active(&row->clone_done.wait) ||
      !row->begin_ns || row->begin_ns > sample->published_ns ||
      sample->published_ns > row->submit_end_ns || row->submit_end_ns > row->end_ns ||
      sample->published_ns > sample->returned_ns || sample->returned_ns > sample->read_begin_ns ||
      sample->read_begin_ns > sample->read_end_ns || sample->read_end_ns > sample->retired_ns ||
      sample->retired_ns > row->end_ns || !sample->retired_ns) {
   error = -EBADMSG; goto spin_unlock;
  }
  if (row->endpoint) {
   if (sample->type != 1 || sample->ifnum || row->clones || row->clone_valid || row->clone_ns ||
       completion_done(&row->clone_done)) { error = -EBADMSG; goto spin_unlock; }
  } else if (sample->type != QDX_RECEIVE_PACKET || sample->ifnum != 30 || row->clones != 1 ||
             !row->clone_valid || row->clone_type != QDX_RECEIVE_PACKET || row->clone_ifnum != 30 ||
             row->clone_length != 24 || row->clone_mod4 || row->clone_ns < row->begin_ns ||
             row->clone_ns > row->end_ns) {
   error = -EBADMSG; goto spin_unlock;
  }
 }
 for (i = 0; i < 24; i += 3) {
  if (rows[i].clone_words[0] || rows[i + 2].clone_words[0] ||
      rows[i].clone_words[5] != rows[i + 2].clone_words[5]) {
   error = -EBADMSG; goto spin_unlock;
  }
  first = ((u64)rows[i].clone_words[5] << 32) | rows[i].clone_words[4];
  last = ((u64)rows[i + 2].clone_words[5] << 32) | rows[i + 2].clone_words[4];
  lifted = first + (u32)(rows[i + 1].sample.words[4] - (u32)first);
  if (last < first || last - first >= BIT_ULL(31) || lifted <= first || lifted > last) {
   error = -EBADMSG; goto spin_unlock;
  }
 }
 /* All validation precedes the only original-module writes. A positive
  * completion count records events already proved to have retired above.
  */
 for (i = 0; i < 24; i++) {
  complete(&rows[i].sample.done);
  samples_signaled++;
  if (!rows[i].endpoint && !completion_done(&rows[i].clone_done)) {
   complete(&rows[i].clone_done);
   clones_signaled++;
  }
 }
 recovered = true;
 error = 0;
spin_unlock:
 spin_unlock_irqrestore(clone_lock, flags);
unlock:
 mutex_unlock(lock);
put:
 module_put(module);
 return error;
}

static ssize_t recovery_control_write(struct file *file, const char __user *buffer,
 size_t count, loff_t *position)
{
 char command[16];
 int error;
 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = 0; strim(command);
 if (strcmp(command, "repair")) return -EINVAL;
 mutex_lock(&recovery_lock);
 error = recovery_run();
 result = error;
 mutex_unlock(&recovery_lock);
 return error ?: count;
}
static const struct file_operations recovery_control_fops = {
 .owner = THIS_MODULE, .write = recovery_control_write,
};
static int recovery_status_show(struct seq_file *seq, void *unused)
{
 mutex_lock(&recovery_lock);
 seq_printf(seq, "allow_writes=%u recovered=%u samples_signaled=%u clones_signaled=%u result=%d text=%lx data=%lx bss=%lx original_probe_runner_failed=1\n",
  allow_writes, recovered, samples_signaled, clones_signaled, result,
  observed_text, observed_data, observed_bss);
 mutex_unlock(&recovery_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 struct dentry *entry;
 if (!allow_writes) return -EPERM;
 directory = debugfs_create_dir("qdx_clock_completion_recovery", NULL);
 if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &recovery_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &recovery_status_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 return 0;
fail:
 debugfs_remove_recursive(directory);
 return entry ? PTR_ERR(entry) : -ENOMEM;
}
static void __exit recovery_exit(void)
{
 debugfs_remove_recursive(directory);
}
module_init(recovery_init);
module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exact consumed clock completion recovery; no sample or queue changes");
