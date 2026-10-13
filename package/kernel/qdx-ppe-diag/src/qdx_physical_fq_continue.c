// SPDX-License-Identifier: GPL-2.0-only
/* Continue only the seven already submitted physical FQ packets; never requeue. */
#include <linux/debugfs.h>
#include <linux/completion.h>
#include <linux/io.h>
#include <linux/rtnetlink.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>
#include <linux/qdx_diag_fq.h>
/* Exact sibling kernel build from owner-observer-manifest.json. */
#include "../linux-6.18.44/drivers/net/ethernet/qualcomm/qdx-drv/qdx.h"
#include "qdx_physical_fq_continue_offsets.h"

struct observe_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
/* Exact io.c private carrier, with geometry checked against that ELF's DWARF. */
struct observe_carrier {
 u32 slot, generation, next;
 int kind, state;
 struct device *dev;
 dma_addr_t dma;
 size_t length;
 unsigned long memory_charge;
 enum dma_data_direction direction;
 bool mapped, charged, accepted;
 struct sk_buff *skb;
 struct page *page;
 void *buffer;
 u64 request_id;
 unsigned long host_charge;
 struct qdx_tx_path *path;
 struct qdx_packet_op *operation;
 struct qdx_dma *diag_region;
 struct qdx_diag_clock_sample *diag_clock;
 struct qdx_packet_recipient recipient;
 struct qdx_port *port;
 struct netdev_queue *queue;
 unsigned int bytes;
};
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct qdx_diag_fq_view) == 4392);
static_assert(sizeof(struct observe_carrier) == 200);
static_assert(offsetof(struct observe_carrier, dma) == 32);
static_assert(offsetof(struct observe_carrier, direction) == 56);
static_assert(offsetof(struct observe_carrier, skb) == 64);
static_assert(offsetof(struct observe_carrier, path) == 104);
static_assert(offsetof(struct observe_carrier, operation) == 112);
static_assert(sizeof(struct qdx_tx_class) == 16);
static_assert(offsetof(struct qdx_tx_class, token) == 8);
static_assert(sizeof(struct qdx_tx_path) == 104);
static_assert(offsetof(struct qdx_tx_path, endpoint) == 32);
static_assert(offsetof(struct qdx_tx_path, open) == 94);
static_assert(offsetof(struct qdx_tx_path, accepted) == 96);
static_assert(offsetof(struct qdx_core, io) == 24);
static_assert(offsetof(struct qdx_endpoint, service) == 8);
static_assert(offsetof(struct qdx_service, kind) == 8);
/* io.c's exact qdx_io DWARF; qdx_io is opaque in the private header. */
#define IO_CARRIERS_LOCK 6056U
#define IO_CHUNKS 6064U
#define IO_SLOTS 8112U
#define SLOT(type, name) ((type *)(FQ_##name##_BASE + FQ_##name))
static unsigned long observe_section(struct module *module, const char *name)
{
 struct observe_sections *sections = (void *)module->sect_attrs;
 const struct bin_attribute *const *entry;
 unsigned int i;

 if (!sections || !sections->grp.bin_attrs) return 0;
 entry = sections->grp.bin_attrs;
 for (i = 0; i < 64 && entry[i]; i++)
  if (!strcmp(entry[i]->attr.name, name)) return (unsigned long)entry[i]->private;
 return 0;
}

static int observe_symbol(const char *name, unsigned long expected)
{
 struct kprobe probe = { .symbol_name = name };
 unsigned long address;
 int error = register_kprobe(&probe);

 if (error) return error;
 address = (unsigned long)probe.addr;
 unregister_kprobe(&probe);
 return address == expected ? 0 : -ESTALE;
}


static const u8 fq_build_id[20] = {
 0x68,0x71,0x02,0xea,0xa7,0x21,0x01,0xd4,0x31,0x51,
 0xb4,0x93,0x4c,0xb4,0x72,0x42,0xa8,0x02,0xe4,0x3d,
};
struct continue_copy {
 struct completion clone_done, original_done;
 u32 originals, clones, length, kind;
 bool original_valid, clone_valid;
 u8 bytes[280];
 struct sk_buff *payload;
};
static_assert(sizeof(struct continue_copy) == 376);
static_assert(offsetof(struct continue_copy, payload) == 368);
static bool allow_writes, started, snapshot_done, table_written, node_written;
static bool verified, self_pinned;
module_param(allow_writes, bool, 0400);
static u32 age_written, age_verified, owner_mask, stage;
static u32 new_hash_flags[7], new_hash[7];
static int result;
static u8 fresh_table[144], moved_table[144];
static u32 moved_node[8];
static struct dentry *directory;
static DEFINE_MUTEX(continue_lock);
#define FLAG(name) (*SLOT(bool, name))
#define WORD(name) (*SLOT(u32, name))
#define POINTER(type, name) (*SLOT(type *, name))

/* Same finite source predicates, corrected static physical endpoint identity.
 * The graph and producers are closed before this read. Firmware enqueue has
 * completed and only reads these TX bytes; no CPU or device writer remains. */
static int continue_owner(struct qdx_endpoint *mirror, struct qdx_tx_path *path,
 struct qdx_diag_fq_view *view, unsigned int index, const u8 expected[110])
{
 struct qdx_core *core = mirror->core;
 struct qdx_io *io = core->io;
 struct observe_carrier **chunks, *record = NULL;
 const u8 *carrier = view->carrier[index], *metadata = view->metadata[index];
 u64 cookie = get_unaligned_le64(metadata + 4);
 u32 buffer = get_unaligned_le32(carrier + 8);
 u32 data = get_unaligned_le32(carrier + 24);
 u32 extent = get_unaligned_le16(carrier + 44);
 u32 length = get_unaligned_le16(carrier + 46), slots;
 unsigned long flags;
 bool valid = false;

 if (!io || !(view->carrier_valid & BIT(index)) || !(view->metadata_valid & BIT(index)) ||
     !(cookie >> 32) || (cookie & GENMASK_ULL(30, 16)) ||
     ((cookie >> 31) & 1) != core->id || length != 110 ||
     data < buffer || data - buffer > extent || length > extent - (data - buffer))
  return -EBADMSG;
 spin_lock_irqsave((spinlock_t *)((u8 *)io + IO_CARRIERS_LOCK), flags);
 slots = *(u32 *)((u8 *)io + IO_SLOTS);
 chunks = (void *)((u8 *)io + IO_CHUNKS);
 if ((cookie & 0xffff) < slots) {
  record = chunks[(cookie & 0xffff) / 256];
  if (record) record += (cookie & 0xffff) % 256;
 }
 if (record && record->state == 2 && record->generation == cookie >> 32 &&
     record->kind == 1 && record->mapped && record->accepted && !record->operation &&
     record->dma == buffer && record->length == extent && record->direction == DMA_TO_DEVICE &&
     record->path == path && record->skb && record->skb->len == length &&
     data - buffer == skb_headroom(record->skb) && !skb_is_nonlinear(record->skb) &&
     path->endpoint->core == core && path->endpoint->service->qdx == mirror->service->qdx &&
     !path->endpoint->dynamic_type && path->endpoint->ifnum == 4 && path->class.tag == 0x6d010000 &&
     !smp_load_acquire(&path->open) && READ_ONCE(path->accepted) == 7)
  valid = !memcmp(record->skb->data, expected, 110);
 spin_unlock_irqrestore((spinlock_t *)((u8 *)io + IO_CARRIERS_LOCK), flags);
 return valid ? 0 : -ESTALE;
}

static int continue_import(void)
{
 static const u16 offsets[8] = {224, 228, 232, 236, 240, 252, 256, 260};
 struct kprobe finder = { .symbol_name = "find_module" };
 struct module *(*find_named)(const char *);
 struct module *fq = NULL, *driver = NULL;
 int (*copy)(enum qdx_diag_fq_range, unsigned int, unsigned int, void *);
 bool (*io_enter)(struct qdx *);
 void (*io_leave)(struct qdx *);
 int (*table_get)(struct qdx_service *, struct qdx_dma *, const struct qdx_owner *, dma_addr_t *);
 void (*table_put)(struct qdx_dma *);
 bool (*table_matches)(struct qdx_dma *, const u8 *), (*table_physical)(struct qdx_dma *);
 u32 (*table_node)(struct qdx_dma *, u32);
 struct qdx_owner owner;
 struct qdx_diag_fq_view *view;
 struct qdx_dma *table;
 struct qdx_endpoint *mirror;
 struct qdx_tx_path *path;
 struct qdx_core *core;
 struct mutex *lock;
 struct sk_buff **prefix;
 unsigned long text, data, bss, note, drv_text;
 u8 bytes[280], *expected, *cpu, *original;
 u64 *age;
 u32 node, table_address, address, metadata, length, sentinel, i, j;
 dma_addr_t registered_address;
 bool entered = false, borrowed = false;
 int error;

 if (verified) return -EALREADY;
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr;
 unregister_kprobe(&finder);
 rcu_read_lock();
 fq = find_named("qdx_physical_fq_diag");
 if (fq && !try_module_get(fq)) fq = NULL;
 driver = find_named("qdx_drv");
 if (driver && !try_module_get(driver)) driver = NULL;
 rcu_read_unlock();
 if (!fq || !driver) { error = -ENOENT; goto put; }
 if (fq->state != MODULE_STATE_LIVE || driver->state != MODULE_STATE_LIVE) {
  error = -ESTALE; goto put;
 }
 text = observe_section(fq, ".text"); data = observe_section(fq, ".data");
 bss = observe_section(fq, ".bss"); note = observe_section(fq, ".note.gnu.build-id");
 drv_text = observe_section(driver, ".text");
 if (!text || !data || !bss || !note || !drv_text ||
     observe_section(fq, ".gnu.linkonce.this_module") != (unsigned long)fq ||
     observe_section(driver, ".gnu.linkonce.this_module") != (unsigned long)driver ||
     !within_module_mem_type(text + FQ_TEXT_SIZE - 1, fq, MOD_TEXT) ||
     !within_module_mem_type(data + FQ_DATA_SIZE - 1, fq, MOD_DATA) ||
     !within_module_mem_type(bss + FQ_BSS_SIZE - 1, fq, MOD_DATA) ||
     !within_module_mem_type(drv_text + DRV_TEXT_SIZE - 1, driver, MOD_TEXT) ||
     !within_module(note, fq) || !within_module(note + 35, fq)) {
  error = -ERANGE; goto put;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), fq_build_id, 20)) { error = -ESTALE; goto put; }
 error = observe_symbol("qdx_physical_fq_diag:phy_snapshot", text + FQ_phy_snapshot);
 if (!error) error = observe_symbol("qdx_xmit", drv_text + DRV_qdx_xmit);
 if (error) goto put;
 copy = (void *)(text + FQ_phy_copy);
 io_enter = (void *)(drv_text + DRV_qdx_io_enter);
 io_leave = (void *)(drv_text + DRV_qdx_io_leave);
 table_get = (void *)(drv_text + DRV_qdx_diag_fq_table_get);
 table_put = (void *)(drv_text + DRV_qdx_diag_fq_table_put);
 table_matches = (void *)(drv_text + DRV_qdx_diag_fq_table_matches);
 table_physical = (void *)(drv_text + DRV_qdx_diag_fq_table_physical);
 table_node = (void *)(drv_text + DRV_qdx_diag_fq_table_node);
 lock = SLOT(struct mutex, control_lock);
 rtnl_lock(); mutex_lock(lock);
 if (!FLAG(pinned) || FLAG(fault) || FLAG(released) || FLAG(rebuilt) || FLAG(imported) || FLAG(on) ||
     !FLAG(cut) || !FLAG(fenced) || !FLAG(cpu_owned) || !FLAG(cpu_selected) ||
     !FLAG(obsolete_retired) || !FLAG(data_closed) || !FLAG(copy_enabled) || FLAG(copy_retired) ||
     WORD(linked) != 4 || WORD(prefix_count) != 9 || WORD(resubmitted) != 7 || WORD(capture_bad) ||
     WORD(markers) != 1 || WORD(marker_wait) != 1 ||
     POINTER(struct qdx_request, request) || POINTER(struct qdx_request, copy_request) ||
     POINTER(struct qdx_packet_op, copy_operation) ||
     SLOT(struct continue_copy, copied)->payload ||
     !skb_queue_empty(SLOT(struct sk_buff_head, quarantine)) ||
     WORD(original_bin) != 0 || (!table_written && WORD(fq_bin) != 1)) {
  error = -EPERM; goto unlock;
 }
 prefix = SLOT(struct sk_buff *, prefix);
 for (i = 0; i < 16; i++)
  if ((i < 9 && (!prefix[i] || prefix[i]->len != 106)) || (i >= 9 && prefix[i])) {
   error = -ESTALE; goto unlock;
  }
 for (i = 0; i < 8; i++) if (SLOT(struct sk_buff *, cpu_queue)[i]) {
  error = -ESTALE; goto unlock;
 }
 if (SLOT(u32, gauge)[1] != 7 || SLOT(u64, admitted)[1] != 7 ||
     SLOT(u64, selected)[1] || SLOT(u64, dropped)[1]) { error = -ESTALE; goto unlock; }
 view = SLOT(struct qdx_diag_fq_view, view);
 table = POINTER(struct qdx_dma, fq_table);
 mirror = POINTER(struct qdx_endpoint, copy_endpoint);
 path = POINTER(struct qdx_tx_path, data_path);
 if (!table || !mirror || !path || view->physical_rebuild != path ||
     mirror->dynamic_type != 65 || mirror->service->kind != QDX_SERVICE_MIRROR ||
     !view->node_valid || view->bf || view->rate || view->wrr || view->aqm) {
  error = -ESTALE; goto unlock;
 }
 core = mirror->core;
 table_address = WORD(fq_table_address); node = WORD(new_node_address);
 expected = SLOT(u8, expected_frames); age = SLOT(u64, enqueue_age);
 cpu = SLOT(u8, cpu_table); original = SLOT(u8, original_table);
 owner = (struct qdx_owner) { .module = fq, .object = view };
 if (!core->image || node < 0x4027b62c || (node - 0x4027b62c) % 280 ||
     node - 0x4027b62c >= 256 * 280 || node < core->image_phys ||
     node - core->image_phys > core->image_size || 280 > core->image_size - (node - core->image_phys) ||
     get_unaligned_le32(view->node + 8) != 1 ||
     get_unaligned_le32(view->node + 16) != 0x6d010000 || view->node[24] ||
     get_unaligned_le32(view->node + 220) != table_address ||
     get_unaligned_le16(view->node + 264) != 2 || get_unaligned_le16(view->node + 266) != 1)
  { error = -EBADMSG; goto unlock; }
 if (!started) {
  if (*SLOT(int, last_error) != -ESTALE || view->carrier_valid != 1 || view->metadata_valid != 1) {
   error = -ESTALE; goto unlock;
  }
  if (!try_module_get(THIS_MODULE)) { error = -ENODEV; goto unlock; }
  self_pinned = true; started = true; stage = 1;
 }
 if (!snapshot_done) {
  error = copy((enum qdx_diag_fq_range)U32_MAX, 0, 144, bytes);
  if (error) goto unlock;
  if (memcmp(bytes, view->table, 144) || get_unaligned_le32(bytes + 24) ||
      get_unaligned_le32(bytes + 96) != 7 || get_unaligned_le32(bytes + 136) != 770 ||
      memcmp(bytes + 8, original + 80, 64)) { error = -EBADMSG; goto unlock; }
  memcpy(fresh_table, bytes, 144);
  for (i = 0; i < 7; i++) {
   address = i ? get_unaligned_le32(view->carrier[i - 1]) : get_unaligned_le32(view->table + 88);
   if (!(view->carrier_valid & BIT(i))) {
    length = address < 0x40000000 ? 56 : 64;
    error = copy(QDX_DIAG_FQ_CARRIER, i, length, view->carrier[i]);
    if (error) goto unlock;
    view->carrier_address[i] = address; view->carrier_valid |= BIT(i);
   }
   if (view->carrier_address[i] != address) { error = -ESTALE; goto unlock; }
   if (!(view->metadata_valid & BIT(i))) {
    error = copy(QDX_DIAG_FQ_METADATA, i, 96, view->metadata[i]);
    if (error) goto unlock;
    view->metadata_valid |= BIT(i);
   }
   error = continue_owner(mirror, path, view, i, expected + 110 * (i + 1));
   if (error) goto unlock;
   owner_mask |= BIT(i);
   new_hash_flags[i] = get_unaligned_le32(view->carrier[i] + 20);
   new_hash[i] = get_unaligned_le16(view->carrier[i] + 50);
   metadata = get_unaligned_le32(view->carrier[i] + 36);
   if ((metadata & 31) || metadata < core->image_phys ||
       metadata - core->image_phys > core->image_size ||
       96 > core->image_size - (metadata - core->image_phys) || !age[i + 1]) {
    error = -ERANGE; goto unlock;
   }
   for (j = 0; j < i; j++)
    if (get_unaligned_le32(view->carrier[j] + 36) == metadata ||
        get_unaligned_le64(view->metadata[j] + 4) == get_unaligned_le64(view->metadata[i] + 4)) {
     error = -ELOOP; goto unlock;
    }
  }
  if (get_unaligned_le32(view->carrier[6]) ||
      view->carrier_address[6] != get_unaligned_le32(view->table + 92)) {
   error = -EBADMSG; goto unlock;
  }
  snapshot_done = true; stage = 2;
 }
 for (i = 0; i < 7; i++) {
  if (!(age_written & BIT(i))) {
   entered = io_enter(mirror->service->qdx);
   if (!entered) { error = -ESHUTDOWN; goto unlock; }
   error = table_get(mirror->service, table, &owner, &registered_address);
   if (error) goto release_borrow;
   borrowed = true;
   if (registered_address != table_address || !table_physical(table) ||
       table_node(table, 0) != node || !table_matches(table, view->table)) {
    error = -ESTALE; goto release_borrow;
   }
   error = continue_owner(mirror, path, view, i, expected + 110 * (i + 1));
   if (error) goto release_borrow;
   metadata = get_unaligned_le32(view->carrier[i] + 36);
   writel(lower_32_bits(age[i + 1]), core->image + metadata - core->image_phys + 72);
   writel(upper_32_bits(age[i + 1]), core->image + metadata - core->image_phys + 76);
   wmb(); age_written |= BIT(i);
   table_put(table); borrowed = false; io_leave(mirror->service->qdx); entered = false;
  }
  if (!(age_verified & BIT(i))) {
   error = copy(QDX_DIAG_FQ_METADATA, i, 96, bytes);
   if (error) goto unlock;
   if (get_unaligned_le64(bytes + 72) != age[i + 1] ||
       memcmp(bytes, view->metadata[i], 72) || memcmp(bytes + 80, view->metadata[i] + 80, 16)) {
    error = -EBADMSG; goto unlock;
   }
   memcpy(view->metadata[i], bytes, 96); age_verified |= BIT(i);
  }
 }
 stage = 3;
 if (!table_written) {
  /* Move the complete real fresh queue to its physical-input bin. */
  memcpy(moved_table, fresh_table + 72, 72);
  memcpy(moved_table + 72, fresh_table, 72);
  memcpy(moved_table + 8, cpu + 8, 8);
  memcpy(moved_table + 28, cpu + 28, 36);
  moved_table[68] = cpu[68];
  sentinel = node + (moved_table[68] ? 228 : 236);
  put_unaligned_le32(sentinel, moved_table); put_unaligned_le32(sentinel, moved_table + 4);
  put_unaligned_le32(table_address + 72, moved_table + 72);
  put_unaligned_le32(table_address + 72, moved_table + 76);
  if (get_unaligned_le32(cpu + 24) != 7 || get_unaligned_le32(cpu + 64) != 770 ||
      get_unaligned_le32(moved_table + 24) != 7 || get_unaligned_le32(moved_table + 64) != 770 ||
      get_unaligned_le32(moved_table + 88) || get_unaligned_le32(moved_table + 92) ||
      get_unaligned_le32(moved_table + 96) || get_unaligned_le32(moved_table + 136) || moved_table[140]) {
   error = -EBADMSG; goto unlock;
  }
  memcpy(moved_node, SLOT(u32, node_values), sizeof(moved_node));
  moved_node[0] = table_address;
  moved_node[1] = moved_node[2] = moved_table[68] ? table_address : node + 228;
  moved_node[3] = moved_node[4] = moved_table[68] ? node + 236 : table_address;
  moved_node[5] = !!moved_table[68]; moved_node[6] = !moved_table[68];
  if (moved_node[7] < 110 || moved_node[7] > U16_MAX) { error = -EINVAL; goto unlock; }
  for (i = 0; i < 8; i++)
   if (((node + offsets[i]) & ~31U) < node || ((node + offsets[i] + 3) | 31U) >= node + 280) {
    error = -EXDEV; goto unlock;
   }
  entered = io_enter(mirror->service->qdx);
  if (!entered) { error = -ESHUTDOWN; goto unlock; }
  error = table_get(mirror->service, table, &owner, &registered_address);
  if (error) goto release_borrow;
  borrowed = true;
  if (registered_address != table_address || !table_physical(table) ||
      table_node(table, 0) != node || !table_matches(table, view->table) ||
      memcmp(view->table, fresh_table, 144)) { error = -ESTALE; goto release_borrow; }
  for (i = 0; i < 7; i++) {
   error = continue_owner(mirror, path, view, i, expected + 110 * (i + 1));
   if (error) goto release_borrow;
  }
  memcpy(qdx_dma_cpu(table), moved_table, 144); dma_wmb();
  memcpy(view->table, moved_table, 144); table_written = true;
  for (i = 0; i < 8; i++) writel(moved_node[i], core->image + node - core->image_phys + offsets[i]);
  wmb(); node_written = true;
  memcpy(SLOT(u32, node_values), moved_node, sizeof(moved_node));
  table_put(table); borrowed = false; io_leave(mirror->service->qdx); entered = false;
 }
 stage = 4;
 error = copy((enum qdx_diag_fq_range)U32_MAX, 0, 144, bytes);
 if (error) goto unlock;
 if (memcmp(bytes, moved_table, 144)) { error = -EBADMSG; goto unlock; }
 error = copy(QDX_DIAG_FQ_NODE, 0, 280, bytes);
 if (error) goto unlock;
 for (i = 0; i < 8; i++)
  if (get_unaligned_le32(bytes + offsets[i]) != moved_node[i]) { error = -EBADMSG; goto unlock; }
 memcpy(view->node, bytes, 280);
 /* All actual owners and carried bytes remain unchanged after both imports. */
 for (i = 0; i < 7; i++) {
  error = continue_owner(mirror, path, view, i, expected + 110 * (i + 1));
  if (error) goto unlock;
 }
 WORD(fq_bin) = WORD(original_bin);
 FLAG(imported) = true; FLAG(rebuilt) = true; *SLOT(int, last_error) = 0;
 verified = true; stage = 5; error = 0;
 self_pinned = false; module_put(THIS_MODULE);
 goto unlock;
release_borrow:
 if (borrowed) { table_put(table); borrowed = false; }
 if (entered) { io_leave(mirror->service->qdx); entered = false; }
unlock:
 mutex_unlock(lock); rtnl_unlock();
put:
 if (driver) module_put(driver);
 if (fq) module_put(fq);
 return error;
}

static ssize_t continue_control_write(struct file *file, const char __user *buffer,
 size_t count, loff_t *position)
{
 char command[16];
 int error;
 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = 0; strim(command);
 if (strcmp(command, "import")) return -EINVAL;
 mutex_lock(&continue_lock);
 error = continue_import(); result = error;
 mutex_unlock(&continue_lock);
 return error ?: count;
}
static const struct file_operations continue_control_fops = {
 .owner = THIS_MODULE, .write = continue_control_write,
};
static int continue_status_show(struct seq_file *seq, void *unused)
{
 unsigned int i;
 mutex_lock(&continue_lock);
 seq_printf(seq, "allow_writes=%u started=%u stage=%u result=%d snapshot_done=%u owner_mask=%x age_written=%x age_verified=%x table_written=%u node_written=%u verified=%u self_pinned=%u original_run_failure_preserved=1\n",
  allow_writes, started, stage, result, snapshot_done, owner_mask, age_written,
  age_verified, table_written, node_written, verified, self_pinned);
 for (i = 0; i < 7; i++)
  seq_printf(seq, "packet=%u carrier_flags=%08x carrier_hash=%04x\n", i + 1, new_hash_flags[i], new_hash[i]);
 mutex_unlock(&continue_lock); return 0;
}
DEFINE_SHOW_ATTRIBUTE(continue_status);
static int __init continue_init(void)
{
 struct dentry *entry;
 if (!allow_writes) return -EPERM;
 directory = debugfs_create_dir("qdx_physical_fq_continue", NULL);
 if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &continue_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &continue_status_fops);
 if (!IS_ERR_OR_NULL(entry)) return 0;
fail:
 debugfs_remove_recursive(directory); return -ENOMEM;
}
static void __exit continue_exit(void)
{
 WARN_ON(self_pinned || (started && !verified));
 debugfs_remove_recursive(directory);
}
module_init(continue_init);
module_exit(continue_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Continue exact occupied physical FQ after diagnostic predicate repair");
