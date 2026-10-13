/* Finite real-packet native TBF handover diagnostic. Not a product interface.
 * Included only by the separate occupied draft. Performance input is unchanged.
 * Reuses the proven022 L0->CPU-parent7/RX15 recall operation and actual skb
 * ownership. It does not import the PPE clock or firmware accounting models.
 */
static bool handover_mode;
static unsigned long long handover_run_id;
module_param(handover_mode, bool, 0400);
module_param(handover_run_id, ullong, 0400);
#define H_ROUTE (0x5a000 + 4 * (Q / 8))
#define H_SHIFT (4 * (Q % 8))
#define H_CROW 0x404070
#define H_EROW 0x406070
#define H_MAP (0x402000 + 16 * Q)
#define H_PORT (0x408000 + 16 * Q)
#define H_CPU_TX (0x024000 + 16 * 192)
#define H_COUNT 4
struct h_item {
    struct sk_buff *skb;
    u8 bytes[106];
    u16 length, before_id, rebuilt_id;
    bool received, consumed, arrived;
};
struct h_decision {
    s64 before_tokens, before_ptokens, before_time;
    s64 after_tokens, after_ptokens, after_time;
    s64 first_mean, first_peak;
    u64 first_check_ns, first_due_ns, publish_ns, complete_ns;
    u32 length, id, tx_before, tx_after;
    bool cpu, issued, done;
};
static struct {
    struct net_device *conduit, *output;
    void __iomem *edma;
    struct sk_buff_head quarantine;
    struct h_item item[H_COUNT];
    struct h_decision decision[H_COUNT];
    bool active, hook, sealed, recall_issued, recalled, maps_restored;
    bool c_touched, e_touched, route_touched, map_touched, port_touched;
    bool cpu_sent, cpu_done, class_one, import_open, complete, empty_abort;
    u16 priority_touched;
    u32 saved_c, expected_c, saved_e, expected_e;
    u32 saved_route, expected_route, expected_map, expected_port;
    u32 returned, bad, native_sent, queued, cpu_tx_before, cpu_tx_after;
    u32 phase, source_tx, recall_tx, resumed_tx, cpu_source_profile, cpu_source_mru, cpu_selector;
    s64 cut_tokens, cut_ptokens, cut_time;
    s64 resumed_tokens, resumed_ptokens, resumed_time;
    u64 cut_ns, recall_ns, cpu_ns, resume_ns;
    int error, stage_error, transport_error;
} handover;
static DEFINE_SPINLOCK(handover_rx_lock);
static u32 rd(u32 off);
static int write_one(u32 off, u32 data);
static void read_row(u32 off, u32 *data, unsigned int words);
static int write_row(u32 off, const u32 *data, unsigned int words);
static int check_ownership(bool partial);
static int load_head(void);
static bool fund_head(u64 now, bool commit);
static int prepare_head(void);
static int grant_head(void);
static int finish_head(void);
static int bind_rule(bool enable);
static int seal_input(void);

/* The exact finite population is four QDXPROB1 groups0..3, sequence0 each,
 * alternating67/106B. Group is the retained item index, not sequence.
 * Only real CPU-returned source0 packets transfer ownership to this module.
 * Source3 ordinary packets still pass; this hook does not create copies.
 */
static rx_handler_result_t handover_receive(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    const struct dsa_oob_tag_info *tag;
    struct h_item *item;
    unsigned long flags;
    unsigned int index, length;
    int offset;
    u8 bytes[106];
    bool valid;

    if (!skb_mac_header_was_set(skb)) return RX_HANDLER_PASS;
    offset = skb_mac_offset(skb);
    if (offset != -ETH_HLEN || skb_headroom(skb) < ETH_HLEN ||
        skb->len + ETH_HLEN < 67 ||
        skb_copy_bits(skb, offset, bytes, 67)) return RX_HANDLER_PASS;
    if (get_unaligned_be16(bytes + 12) != ETH_P_IP || bytes[14] != 0x45 ||
        bytes[23] != IPPROTO_UDP ||
        get_unaligned_be32(bytes + 26) != 0xc0a80190 ||
        get_unaligned_be32(bytes + 30) != 0xc0a80173 ||
        get_unaligned_be16(bytes + 36) != 45987 ||
        memcmp(bytes + 42, "QDXPROB1", 8) ||
        get_unaligned_be64(bytes + 50) != handover_run_id)
        return RX_HANDLER_PASS;
    tag = skb_ext_find(skb, SKB_EXT_DSA_OOB);
    if (!tag || tag->port != 0) return RX_HANDLER_PASS;
    length = skb->len + ETH_HLEN;
    index = get_unaligned_be32(bytes + 59);
    spin_lock_irqsave(&handover_rx_lock, flags);
    valid = handover.recall_issued && !handover.maps_restored &&
            !skb_vlan_tag_present(skb) && bytes[58] == 1 &&
            get_unaligned_be32(bytes + 63) == 0 &&
            index == 1 + handover.returned && index < H_COUNT &&
            length == (index & 1 ? 106 : 67) &&
            get_unaligned_be16(bytes + 16) + ETH_HLEN == length &&
            get_unaligned_be16(bytes + 38) + 34 == length &&
            !skb_copy_bits(skb, offset, bytes, length);
    if (valid) {
        item = &handover.item[index];
        valid = !item->skb && !item->received && item->length == length;
        if (valid) {
            item->skb = skb;
            item->received = true;
            memcpy(item->bytes, bytes, length);
            handover.returned++;
        }
    }
    if (!valid) handover.bad++;
    skb_push(skb, ETH_HLEN);
    skb_reset_mac_header(skb);
    skb_ext_del(skb, SKB_EXT_DSA_OOB);
    spin_unlock_irqrestore(&handover_rx_lock, flags);
    if (!valid) skb_queue_tail(&handover.quarantine, skb);
    return RX_HANDLER_CONSUMED;
}

/* Stable original chain: no assumed empty ID, no packet reconstruction. */
static int handover_chain(unsigned int first, unsigned int count, bool imported)
{
    u32 head = rd(HEAD), id, tail, lo, hi;
    unsigned int i, j;
    if (!(rd(DEQ) & 1) || in_flight || first + count > H_COUNT)
        return -EBUSY;
    if (!count) return (head & 1) && !(rd(USED) & 0xfff) ? 0 : -EAGAIN;
    if (head & 1) return -EAGAIN;
    id = (head >> 12) & 0x7ff;
    tail = (head >> 1) & 0x7ff;
    for (i = 0; i < count; i++) {
        struct h_item *item = &handover.item[first + i];
        lo = rd(0x9c0000 + 64 * id);
        hi = rd(0x9c0004 + 64 * id);
        if (((lo >> 24) | ((hi & 63) << 8)) != item->length ||
            (lo & 0xfff) != (imported ? 0 : 3)) return -EBADMSG;
        for (j = 0; j < i; j++)
            if (id == (imported ? handover.item[first+j].rebuilt_id :
                                 handover.item[first+j].before_id)) return -ELOOP;
        if (imported) item->rebuilt_id = id;
        else item->before_id = id;
        if ((i + 1 == count) != (id == tail)) return -EAGAIN;
        id = rd(0x890000 + 16 * id) & 0x7ff;
    }
    return rd(HEAD) == head ? 0 : -ESTALE;
}

static int handover_owned_rows(void)
{
    u32 value;
    if (!handover.active) return 0;
    if (handover.phase && (((rd(0x63004) >> 2) & 3) != handover.cpu_source_profile ||
        rd(0x810000 + 16 * (handover.cpu_source_profile * 256 + 4)) != handover.cpu_selector))
        return -ESTALE;
    if (handover.c_touched && rd(H_CROW) != handover.expected_c) return -ESTALE;
    if (handover.e_touched && rd(H_EROW) != handover.expected_e) return -ESTALE;
    if (handover.route_touched) {
        value = readl(handover.edma + H_ROUTE);
        if (((value >> H_SHIFT) & 15) != ((handover.expected_route >> H_SHIFT) & 15))
            return -ESTALE;
    }
    return 0;
}

static int handover_prepare(void)
{
    struct device_node *np;
    struct resource resource;
    struct Qdisc *qdisc;
    u32 map, c, e, row[3], other, cpu_mru, cpu_profile, cpu_selector;
    unsigned int i;
    int err;

    if (!handover_mode || !control_fast || !handover_run_id || !reserved || failure ||
        handover.active || worker || ever_armed || blackhole_sport ||
        rate_bps != 80 || burst_bytes != 212 ||
        peak.rate_bytes_ps != 20 || peak_burst != 106 ||
        data_length_a != 67 || data_length_b != 106 || accept_handshake)
        return -EPERM;
    err = check_ownership(false);
    if (err) return err;
    if (!(rd(HEAD) & 1) || (rd(USED) & 0xfff)) return -EBUSY;
    /* Read CPU port0's actual ingress profile and its destination-port4 row.
     * Priority profile4 is the row's OUTPUT, not the CPU ingress profile.
     * All live profile4 destination/hash relations were checked at reserve.
     */
    cpu_mru = rd(0x63004);
    cpu_profile = (cpu_mru >> 2) & 3;
    cpu_selector = rd(0x810000 + 16 * (cpu_profile * 256 + 4));
    if ((cpu_selector & 4095) != (192 << 4 | 4)) return -EXDEV;
    if ((rd(0x440000) & 15) || (rd(0x446000) & 15)) return -EXDEV;
    read_row(0x45e000, row, 3);
    if (row[2] & 0x30) return -EXDEV;
    read_row(0x474000, row, 2);
    if (row[1] & 0x10) return -EXDEV;
    map = expected_map;
    c = rd(0x404000 + 16 * ((map & 63) * 8 + ((map >> 6) & 7)));
    e = rd(0x406000 + 16 * ((map & 63) * 8 + ((map >> 9) & 7)));
    if ((c & 255) >= 160 || (e & 255) >= 160) return -ERANGE;
    for (i = 0; i < 300; i++) {
        if (i == Q) continue;
        other = leaf_maps[i];
        if (!(other & 63) && (((other >> 6) & 7) == 7 ||
                             ((other >> 9) & 7) == 7)) return -EBUSY;
        if ((rd(0x404000 + 16 * ((other & 63) * 8 + ((other >> 6) & 7))) & 255) == (c & 255) ||
            (rd(0x406000 + 16 * ((other & 63) * 8 + ((other >> 9) & 7))) & 255) == (e & 255))
            return -EBUSY;
    }
    memset(&handover, 0, sizeof(handover));
    skb_queue_head_init(&handover.quarantine);
    handover.active = true;
    handover.cpu_source_mru = cpu_mru;
    handover.cpu_source_profile = cpu_profile;
    handover.cpu_selector = cpu_selector;
    handover.expected_map = expected_map;
    handover.expected_port = saved_port;
    handover.saved_c = rd(H_CROW); handover.expected_c = c;
    handover.saved_e = rd(H_EROW); handover.expected_e = e;
    for (i = 0; i < H_COUNT; i++) handover.item[i].length = i & 1 ? 106 : 67;
    np = of_find_compatible_node(NULL, NULL, "qualcomm,ipq8074-edma");
    if (!np) return -ENODEV;
    err = of_address_to_resource(np, 0, &resource);
    of_node_put(np);
    if (err) return err;
    handover.edma = ioremap(resource.start, resource_size(&resource));
    if (!handover.edma) return -ENOMEM;
    if (!(readl(handover.edma + 0x48018) & 1)) return -ENODEV;
    handover.saved_route = handover.expected_route = readl(handover.edma + H_ROUTE);
    handover.output = dev_get_by_name(&init_net, "lan2");
    handover.conduit = dev_get_by_name(&init_net, "eth0");
    if (!handover.output || !handover.conduit) return -ENODEV;
    rtnl_lock();
    qdisc = rtnl_dereference(handover.output->qdisc);
    if (!netif_running(handover.output) || !netif_running(handover.conduit) ||
        !qdisc || strcmp(qdisc->ops->id, "noqueue") ||
        rtnl_dereference(handover.conduit->rx_handler)) err = -EBUSY;
    else {
        err = netdev_rx_handler_register(handover.conduit, handover_receive, NULL);
        if (!err) handover.hook = true;
    }
    rtnl_unlock();
    if (err) return err;
    err = write_one(ENQ, saved_enq);
    if (!err) err = bind_rule(true);
    if (!err) handover.phase = 1;
    return err;
}

/* Close input only after the finite source has completed. No open/drain is
 * replayed: partial recall continues by observing the original command.
 */
static int handover_recall(void)
{
    u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 }, value;
    u64 until;
    int err;
    if (!handover.recall_issued) {
        err = handover_chain(1, 3, false);
        if (err) return err;
        mechanical_disabled = false;
        err = write_row(CFG, cfg, 3);
        if (err) return err;
        mechanical_disabled = true;
        prepared = false; head_valid = false;
        head_cost = head_peak_cost = next_due = 0;
        handover.cut_tokens = tokens; handover.cut_ptokens = ptokens;
        handover.cut_time = credit_time; handover.cut_ns = ktime_get_ns();
        if (!handover.c_touched) {
            handover.c_touched = true;
            err = write_one(H_CROW, handover.expected_c);
            if (err) return err;
        }
        if (!handover.e_touched) {
            handover.e_touched = true;
            err = write_one(H_EROW, handover.expected_e);
            if (err) return err;
        }
        if (!handover.route_touched) {
            handover.route_touched = true;
            handover.expected_route = (handover.saved_route & ~(15U << H_SHIFT)) | (15U << H_SHIFT);
            writel(handover.expected_route, handover.edma + H_ROUTE);
            if (readl(handover.edma + H_ROUTE) != handover.expected_route) return -EIO;
        }
        if (!handover.map_touched) {
            handover.map_touched = true;
            handover.expected_map = (expected_map & ~4095U) | (7 << 6) | (7 << 9);
            err = write_one(H_MAP, handover.expected_map);
            if (err) return err;
        }
        if (!handover.port_touched) {
            handover.port_touched = true;
            handover.expected_port = saved_port & ~15U;
            err = write_one(H_PORT, handover.expected_port);
            if (err) return err;
        }
        err = check_ownership(false);
        if (err) return err;
        handover.recall_issued = true;
        err = write_one(DEQ, saved_gate & ~1);
        if (err) return err;
    }
    /* Resume an already-issued evacuation only for originals still in the
     * held queue. No original skb is sent/replayed by this operation. */
    if (handover.returned < 3 && (rd(DEQ) & 1)) {
        err = handover_chain(1 + handover.returned, 3 - handover.returned, false);
        if (err) return err;
        err = write_one(DEQ, saved_gate & ~1);
        if (err) return err;
    }
    until = ktime_get_ns() + 100 * NSEC_PER_MSEC;
    while (READ_ONCE(handover.returned) != 3 && !READ_ONCE(handover.bad) && ktime_get_ns() < until)
        usleep_range(50, 100);
    err = write_one(DEQ, saved_gate | 1);
    if (err) return err;
    synchronize_net();
    if (handover.bad) return -EBADMSG;
    if (handover.returned != 3) return -ETIMEDOUT;
    err = handover_chain(0, 0, false);
    if (err) return err;
    if (!handover.maps_restored) {
        handover.expected_map = expected_map;
        err = write_one(H_MAP, expected_map);
        if (err) return err;
        handover.expected_port = saved_port;
        err = write_one(H_PORT, saved_port);
        if (err) return err;
        handover.expected_c = handover.saved_c;
        err = write_one(H_CROW, handover.expected_c);
        if (err) return err;
        handover.expected_e = handover.saved_e;
        err = write_one(H_EROW, handover.expected_e);
        if (err) return err;
        value = readl(handover.edma + H_ROUTE);
        handover.expected_route = (value & ~(15U << H_SHIFT)) | (handover.saved_route & (15U << H_SHIFT));
        writel(handover.expected_route, handover.edma + H_ROUTE);
        if (readl(handover.edma + H_ROUTE) != handover.expected_route) return -EIO;
        handover.maps_restored = true;
    }
    handover.recall_tx = rd(TX);
    if ((u32)(handover.recall_tx - handover.decision[0].tx_after) != 3) return -EBADMSG;
    handover.recall_ns = ktime_get_ns();
    handover.recalled = true;
    return 0;
}

/* Native eligibility comes from the actual next original's length. Each
 * unsuccessful calculation remains prospective; only publication commits it.
 */
static int handover_wait_credit(unsigned int index)
{
    struct h_decision *d = &handover.decision[index];
    s64 elapsed, mean, peak_credit;
    u64 now, until = ktime_get_ns() + 15 * NSEC_PER_SEC;
    ktime_t delay;
    if (!d->first_check_ns) {
        now = ktime_get_ns();
        elapsed = min_t(s64, now - credit_time, buffer_ns);
        mean = min_t(s64, elapsed + tokens, buffer_ns) - psched_l2t_ns(&rate, head_length);
        peak_credit = min_t(s64, elapsed + ptokens, peak_buffer_ns) - psched_l2t_ns(&peak, head_length);
        d->first_check_ns = now; d->first_mean = mean; d->first_peak = peak_credit;
        d->first_due_ns = now + max_t(s64, 0, max(-mean, -peak_credit));
    }
    for (;;) {
        now = ktime_get_ns();
        if (fund_head(now, false)) return 0;
        if (now >= until) return -ETIMEDOUT;
        delay = ns_to_ktime(next_due > now ? next_due - now : 1);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_hrtimeout(&delay, HRTIMER_MODE_REL);
        __set_current_state(TASK_RUNNING);
        if (kthread_should_stop()) return -EINTR;
    }
}

static int handover_packet_check(unsigned int index)
{
    struct h_item *item = &handover.item[index];
    struct sk_buff *skb = item->skb;
    u8 bytes[106];
    if (!skb || !item->received || item->consumed || skb->len != item->length ||
        skb_copy_bits(skb, 0, bytes, skb->len) ||
        memcmp(bytes, item->bytes, skb->len)) return -EBADMSG;
    return 0;
}

static int handover_send(unsigned int index)
{
    struct h_item *item = &handover.item[index];
    struct sk_buff *skb = item->skb;
    int result = handover_packet_check(index);
    if (result) return result;
    skb->dev = handover.output;
    skb->protocol = htons(ETH_P_IP); skb->ip_summed = CHECKSUM_NONE;
    skb_reset_mac_header(skb); skb_set_network_header(skb, ETH_HLEN);
    skb_set_transport_header(skb, ETH_HLEN + 20);
    skb_set_queue_mapping(skb, 0); skb->priority = 0;
    item->skb = NULL;
    item->consumed = true; /* dev_queue_xmit consumes even on a reported drop. */
    result = dev_queue_xmit(skb);
    if (net_xmit_eval(result)) {
        handover.transport_error = result < 0 ? result : -ENOBUFS;
        return handover.transport_error;
    }
    return 0;
}

static int handover_cpu_step(void)
{
    struct h_decision *d = &handover.decision[1];
    u64 until;
    int err;
    if (!handover.recalled || !handover.maps_restored || handover.bad) return -EPERM;
    if (!handover.cpu_sent) {
        err = handover_packet_check(1);
        if (err) return err;
        if (rd(0x430000 + 16 * 192) & 1) return -EBUSY;
        head_length = handover.item[1].length;
        head_cost = psched_l2t_ns(&rate, head_length);
        head_peak_cost = psched_l2t_ns(&peak, head_length);
        err = handover_wait_credit(1);
        if (err) return err;
        d->before_tokens = tokens; d->before_ptokens = ptokens; d->before_time = credit_time;
        d->length = head_length; d->cpu = true;
        handover.cpu_tx_before = rd(H_CPU_TX);
        d->publish_ns = ktime_get_ns();
        if (!fund_head(d->publish_ns, true)) return -EAGAIN;
        d->after_tokens = tokens; d->after_ptokens = ptokens; d->after_time = credit_time;
        d->issued = handover.cpu_sent = true;
        err = handover_send(1);
        if (err) return err;
    }
    until = ktime_get_ns() + NSEC_PER_SEC;
    do {
        handover.cpu_tx_after = rd(H_CPU_TX);
        /* q192 is shared with legitimate native output. This is progress,
         * not identity or completion of our original; wire attestation below
         * remains the release boundary. dev_queue_xmit owns the skb now. */
        if ((u32)(handover.cpu_tx_after - handover.cpu_tx_before) >= 1) break;
        usleep_range(50, 100);
    } while (ktime_get_ns() < until);
    if (!(u32)(handover.cpu_tx_after - handover.cpu_tx_before)) return -ETIMEDOUT;
    d->tx_before = handover.cpu_tx_before; d->tx_after = handover.cpu_tx_after;
    d->complete_ns = ktime_get_ns(); d->done = true;
    handover.cpu_ns = d->complete_ns; handover.cpu_done = true;
    head_valid = false; prepared = false; head_cost = head_peak_cost = next_due = 0;
    return 0;
}

static int handover_reimport(void)
{
    u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
    unsigned int i;
    u64 until;
    int err;
    if (!handover.cpu_done || !handover.maps_restored || handover.bad) return -EPERM;
    if (!handover.import_open) {
        err = check_ownership(false);
        if (err) return err;
        for (i = 0; i < 16; i++) {
            if (handover.priority_touched & BIT(i)) continue;
            handover.priority_touched |= BIT(i);
            err = write_one(CONTROL_PRIORITY(i), (saved_priority[i] & ~15U) | 1);
            if (err) return err;
        }
        handover.class_one = true;
        err = write_one(ENQ, saved_enq);
        if (err) return err;
        handover.import_open = true;
    }
    for (i = 2; i < H_COUNT; i++) {
        if (handover.item[i].arrived) continue;
        if (!handover.item[i].consumed) {
            err = handover_chain(2, i - 2, true);
            if (err) return err;
            err = handover_send(i);
            if (handover.item[i].consumed) handover.native_sent++;
            if (err) return err;
        }
        until = ktime_get_ns() + NSEC_PER_SEC;
        do {
            err = handover_chain(2, i - 1, true);
            if (err != -EAGAIN) break;
            usleep_range(50, 100);
        } while (ktime_get_ns() < until);
        if (err) return err;
        if (!handover.item[i].arrived) {
            handover.item[i].arrived = true;
            handover.queued++;
        }
    }
    err = write_one(ENQ, saved_enq | 1);
    if (err) return err;
    for (i = 0; i < 16; i++) {
        if (!(handover.priority_touched & BIT(i))) continue;
        err = write_one(CONTROL_PRIORITY(i), saved_priority[i] & ~15U);
        if (err) return err;
        handover.priority_touched &= ~BIT(i);
    }
    handover.class_one = false;
    mechanical_disabled = false;
    err = write_row(CFG, cfg, 3);
    if (err) return err;
    mechanical_disabled = true;
    prepared = head_valid = false; head_cost = head_peak_cost = next_due = 0;
    last_tx = rd(TX); handover.resumed_tx = last_tx;
    if (last_tx != handover.recall_tx) return -ESTALE;
    handover.resumed_tokens = tokens; handover.resumed_ptokens = ptokens;
    handover.resumed_time = credit_time; handover.resume_ns = ktime_get_ns();
    return check_ownership(false);
}

static int handover_hardware_step(unsigned int index)
{
    struct h_decision *d = &handover.decision[index];
    u64 until;
    int err;
    if (!d->issued) {
        err = load_head();
        if (err || !head_valid) return err ? err : -ENODATA;
        if (head_length != handover.item[index].length) return -EBADMSG;
        d->length = head_length; d->id = head_id; d->tx_before = rd(TX);
        err = prepare_head();
        if (!err) err = handover_wait_credit(index);
        if (err) return err;
        d->before_tokens = tokens; d->before_ptokens = ptokens; d->before_time = credit_time;
        err = grant_head();
        d->issued = in_flight;
        d->publish_ns = issue_time;
        d->after_tokens = tokens; d->after_ptokens = ptokens; d->after_time = credit_time;
        if (err) return err;
    }
    until = ktime_get_ns() + FLIGHT_NS;
    while (in_flight) {
        err = finish_head();
        if (err) return err;
        if (!in_flight) break;
        if (ktime_get_ns() >= until) return -ETIMEDOUT;
        usleep_range(5, 10);
    }
    d->tx_after = rd(TX); d->complete_ns = ktime_get_ns(); d->done = true;
    return (u32)(d->tx_after - d->tx_before) == 1 ? 0 : -EBADMSG;
}

/* One finite target-side actor performs the time-dependent sequence. Stage is
 * advanced only after its operation; error keeps every original owner visible.
 */
static int handover_worker(void *unused)
{
    int err = 0;
    mutex_lock(&lock);
    while (!err && handover.phase < 8 && !kthread_should_stop()) {
        switch (handover.phase) {
        case 2:
            err = handover_hardware_step(0);
            if (!err) {
                err = load_head();
                if (!err) err = prepare_head(); /* exercise a real cached head at the cut */
            }
            if (!err) handover.phase = 3;
            break;
        case 3:
            err = handover_recall();
            if (!err) handover.phase = 4;
            break;
        case 4:
            err = handover_cpu_step();
            if (!err) handover.phase = 5;
            break;
        case 5:
            err = handover_reimport();
            if (!err) handover.phase = 6;
            break;
        case 6:
            err = handover_hardware_step(2);
            if (!err) handover.phase = 7;
            break;
        case 7:
            err = handover_hardware_step(3);
            if (!err) handover.phase = 8;
            break;
        default: err = -EINVAL;
        }
    }
    if (err) {
        write_one(DEQ, saved_gate | 1);
        write_one(ENQ, saved_enq | 1);
    }
    handover.error = err;
    handover.stage_error = handover.phase;
    running = false;
    mutex_unlock(&lock);
    wait_event_interruptible(stop_wait, kthread_should_stop());
    return 0;
}

static int handover_start(bool continuation)
{
    int err;
    if (!handover.active || failure || running || handover.complete) return -EPERM;
    if (!continuation) {
        if (handover.phase != 1) return -EPERM;
        if (!handover.sealed) {
            err = seal_input();
            if (err) return err;
            handover.sealed = true;
        }
        err = handover_chain(0, H_COUNT, false);
        if (err) return err;
        started = ktime_get_ns();
        tokens = buffer_ns; ptokens = peak_buffer_ns; credit_time = started;
        handover.source_tx = rd(TX);
        handover.phase = 2;
    } else {
        if (handover.phase < 2 || handover.phase >= 8 || handover.bad || handover.transport_error ||
            !skb_queue_empty(&handover.quarantine)) return -EPERM;
        err = check_ownership(false);
        if (err) return err;
    }
    if (worker) { kthread_stop(worker); worker = NULL; }
    running = true;
    worker = kthread_run(handover_worker, NULL, "qdx-tbf-handover");
    if (IS_ERR(worker)) {
        err = PTR_ERR(worker); worker = NULL; running = false;
        return err;
    }
    return 0;
}

static int handover_release(void)
{
    unsigned int i;
    if (!handover.active) return 0;
    if ((handover.phase && !handover.complete && !handover.empty_abort) ||
        running || in_flight || handover.bad ||
        !skb_queue_empty(&handover.quarantine)) return -EBUSY;
    for (i = 1; i < H_COUNT; i++)
        if (handover.item[i].skb) return -EBUSY;
    if (handover.hook) {
        rtnl_lock(); netdev_rx_handler_unregister(handover.conduit); rtnl_unlock();
        handover.hook = false;
    }
    if (handover.output) dev_put(handover.output);
    if (handover.conduit) dev_put(handover.conduit);
    if (handover.edma) iounmap(handover.edma);
    handover.output = handover.conduit = NULL; handover.edma = NULL;
    handover.active = false;
    return 0;
}

static void handover_status(struct seq_file *s)
{
    unsigned int i;
    seq_printf(s, "handover active=%u phase=%u error=%d stage_error=%d transport_error=%d hook=%u returned=%u bad=%u quarantine=%u recalled=%u maps_restored=%u cpu_sent=%u cpu_done=%u native_sent=%u queued=%u class_one=%u priority_touched=%04x complete=%u empty_abort=%u\n",
        handover.active,handover.phase,handover.error,handover.stage_error,handover.transport_error,handover.hook,
        handover.returned,handover.bad,skb_queue_len(&handover.quarantine),handover.recalled,
        handover.maps_restored,handover.cpu_sent,handover.cpu_done,handover.native_sent,
        handover.queued,handover.class_one,handover.priority_touched,handover.complete,handover.empty_abort);
    seq_printf(s, "handover_selector cpu_source_profile=%u cpu_source_mru=%08x destination4=%08x priority_profile=4\n",
        handover.cpu_source_profile,handover.cpu_source_mru,handover.cpu_selector);
    seq_printf(s, "handover_credit cut=%lld,%lld,%lld resumed=%lld,%lld,%lld time=%llu,%llu,%llu,%llu tx=%u,%u,%u\n",
        handover.cut_tokens,handover.cut_ptokens,handover.cut_time,handover.resumed_tokens,
        handover.resumed_ptokens,handover.resumed_time,handover.cut_ns,handover.recall_ns,
        handover.cpu_ns,handover.resume_ns,handover.source_tx,handover.recall_tx,handover.resumed_tx);
    for (i = 0; i < H_COUNT; i++) {
        struct h_decision *d = &handover.decision[i];
        struct h_item *item = &handover.item[i];
        seq_printf(s, "handover_item index=%u length=%u skb=%u received=%u consumed=%u arrived=%u before_id=%u rebuilt_id=%u\n",
            i,item->length,item->skb != NULL,item->received,item->consumed,item->arrived,item->before_id,item->rebuilt_id);
        seq_printf(s, "handover_decision index=%u cpu=%u issued=%u done=%u length=%u id=%u before=%lld,%lld,%lld after=%lld,%lld,%lld first=%llu,%lld,%lld,%llu publication=%llu completion=%llu tx=%u,%u\n",
            i,d->cpu,d->issued,d->done,d->length,d->id,d->before_tokens,d->before_ptokens,
            d->before_time,d->after_tokens,d->after_ptokens,d->after_time,d->first_check_ns,
            d->first_mean,d->first_peak,d->first_due_ns,d->publish_ns,d->complete_ns,d->tx_before,d->tx_after);
    }
}
