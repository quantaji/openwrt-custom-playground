// SPDX-License-Identifier: GPL-2.0-only
/* Read one actual occupied owner. No NSS command, packet access or mutation. */
#include <linux/debugfs.h>
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
#include "qdx_physical_fq_owner_offsets.h"

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
static const u8 fq_build_id[20] = {
 0x68,0x71,0x02,0xea,0xa7,0x21,0x01,0xd4,0x31,0x51,
 0xb4,0x93,0x4c,0xb4,0x72,0x42,0xa8,0x02,0xe4,0x3d,
};
static struct dentry *directory;
static DEFINE_MUTEX(observe_lock);

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

static int observe_owner(struct seq_file *seq)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct module *(*find_named)(const char *);
 struct module *fq = NULL, *driver = NULL;
 struct mutex *lock;
 struct qdx_diag_fq_view *view;
 struct qdx_tx_path *path;
 struct qdx_endpoint *mirror;
 struct qdx_core *core;
 struct qdx_io *io;
 struct observe_carrier **chunks, *record, saved = {};
 unsigned long text, data, bss, note, drv_text, flags;
 u64 cookie = 0;
 u32 buffer = 0, packet_data = 0, slots = 0, core_id = 0;
 u32 total = 0, packet_length = 0, buffer_length = 0;
 u32 skb_len = 0, headroom = 0, path_tag = 0, path_accepted = 0, path_ifnum = 0;
 int path_kind = -1;
 bool present = false, base_valid = false, physical_valid = false;
 bool path_matches = false, core_matches = false, qdx_matches = false, path_open = false;
 bool skb_read = false;
 unsigned int stage = 0;
 int error;

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
 text = observe_section(fq, ".text");
 data = observe_section(fq, ".data");
 bss = observe_section(fq, ".bss");
 note = observe_section(fq, ".note.gnu.build-id");
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
     memcmp((void *)(note + 16), fq_build_id, 20)) {
  error = -ESTALE; goto put;
 }
 /* The stripped runtime driver has no GNU build-id. Its independently recorded
  * file hash maps to this unstripped ELF; check its actual exported qdx_xmit text relation here. */
 error = observe_symbol("qdx_physical_fq_diag:phy_snapshot", text + FQ_phy_snapshot);
 if (!error) error = observe_symbol("qdx_xmit", drv_text + DRV_qdx_xmit);
 if (error) goto put;
 stage = 1;
 lock = SLOT(struct mutex, control_lock);
 mutex_lock(lock);
 if (!*SLOT(bool, pinned) || *SLOT(bool, fault) || !*SLOT(bool, data_closed) ||
     *SLOT(bool, imported) || *SLOT(u32, resubmitted) != 7 ||
     *SLOT(int, last_error) != -ESTALE || *SLOT(struct qdx_request *, request) ||
     *SLOT(struct qdx_packet_op *, copy_operation)) {
  error = -EPERM; goto unlock;
 }
 view = SLOT(struct qdx_diag_fq_view, view);
 path = *SLOT(struct qdx_tx_path *, data_path);
 mirror = *SLOT(struct qdx_endpoint *, copy_endpoint);
 if (!path || !mirror || view->physical_rebuild != path ||
     !(view->carrier_valid & 1) || !(view->metadata_valid & 1)) {
  error = -ENODATA; goto unlock;
 }
 core = mirror->core;
 io = core->io;
 core_id = core->id;
 cookie = get_unaligned_le64(view->metadata[0] + 4);
 buffer = get_unaligned_le32(view->carrier[0] + 8);
 packet_data = get_unaligned_le32(view->carrier[0] + 24);
 packet_length = get_unaligned_le16(view->carrier[0] + 46);
 buffer_length = get_unaligned_le16(view->carrier[0] + 44);
 total = get_unaligned_le32(view->table + 24) + get_unaligned_le32(view->table + 96);
 if (!io || !(cookie >> 32) || (cookie & GENMASK_ULL(30, 16)) ||
     ((cookie >> 31) & 1) != core_id) { error = -EBADMSG; goto unlock; }
 stage = 2;
 spin_lock_irqsave((spinlock_t *)((u8 *)io + IO_CARRIERS_LOCK), flags);
 slots = *(u32 *)((u8 *)io + IO_SLOTS);
 chunks = (void *)((u8 *)io + IO_CHUNKS);
 record = NULL;
 if ((cookie & 0xffff) < slots) {
  record = chunks[(cookie & 0xffff) / 256];
  if (record) record += (cookie & 0xffff) % 256;
 }
 if (record) {
  present = true;
  saved = *record;
  base_valid = record->state == 2 && record->generation == cookie >> 32 &&
   record->mapped && record->dma == buffer && buffer_length <= record->length &&
   packet_data >= buffer && packet_data - buffer <= buffer_length && packet_length &&
   packet_length <= buffer_length - (packet_data - buffer);
  path_matches = record->path == path;
  /* Only dereference the actual retained path, never a mismatching record path. */
  if (path_matches) {
   path_tag = path->class.tag;
   path_accepted = READ_ONCE(path->accepted);
   path_open = smp_load_acquire(&path->open);
   path_ifnum = path->endpoint->ifnum;
   path_kind = path->endpoint->service->kind;
   core_matches = path->endpoint->core == core;
   qdx_matches = path->endpoint->service->qdx == mirror->service->qdx;
  }
  if (record->state == 2 && record->generation == cookie >> 32 &&
      record->accepted && record->skb) {
   skb_len = record->skb->len;
   headroom = skb_headroom(record->skb);
   skb_read = true;
  }
  physical_valid = base_valid && record->kind == 1 && record->accepted && !record->operation &&
   path_matches && skb_read && record->direction == DMA_TO_DEVICE && packet_length <= 2048 &&
   core_matches && qdx_matches && path_kind == QDX_SERVICE_SHAPER && path_ifnum == 4 &&
   path_tag == 0x6d010000 && !path_open && path_accepted == total &&
   record->length == buffer_length && skb_len == packet_length && packet_data - buffer == headroom;
 }
 spin_unlock_irqrestore((spinlock_t *)((u8 *)io + IO_CARRIERS_LOCK), flags);
 stage = 3;
 error = 0;
unlock:
 mutex_unlock(lock);
 seq_printf(seq, "stage=%u result=%d read_only=1 cookie=%016llx core=%u slots=%u total=%u carrier_buffer=%08x carrier_data=%08x carrier_length=%u carrier_buffer_length=%u\n",
  stage, error, (unsigned long long)cookie, core_id, slots, total, buffer, packet_data, packet_length, buffer_length);
 seq_printf(seq, "record_present=%u slot=%u generation=%u kind=%d state=%d mapped=%u dma=%016llx length=%zu direction=%d accepted=%u operation=%px skb=%px path=%px\n",
  present, saved.slot, saved.generation, saved.kind, saved.state, saved.mapped,
  (unsigned long long)saved.dma, saved.length, saved.direction, saved.accepted,
  saved.operation, saved.skb, saved.path);
 seq_printf(seq, "base_valid=%u physical_valid=%u path_matches=%u core_matches=%u qdx_matches=%u path_kind=%d path_ifnum=%u path_tag=%08x path_open=%u path_accepted=%u skb_read=%u skb_length=%u skb_headroom=%u\n",
  base_valid, physical_valid, path_matches, core_matches, qdx_matches, path_kind, path_ifnum,
  path_tag, path_open, path_accepted, skb_read, skb_len, headroom);
put:
 if (driver) module_put(driver);
 if (fq) module_put(fq);
 if (stage < 1) seq_printf(seq, "stage=%u result=%d read_only=1 artifact_or_symbol_guard=1\n", stage, error);
 return error;
}

static int observe_status_show(struct seq_file *seq, void *unused)
{
 mutex_lock(&observe_lock);
 observe_owner(seq);
 mutex_unlock(&observe_lock);
 /* Preserve diagnostic text even on a refused read; result carries errno. */
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(observe_status);
static int __init observe_init(void)
{
 struct dentry *entry;
 directory = debugfs_create_dir("qdx_physical_fq_owner_observe", NULL);
 if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
 entry = debugfs_create_file("status", 0400, directory, NULL, &observe_status_fops);
 if (!IS_ERR_OR_NULL(entry)) return 0;
 debugfs_remove_recursive(directory);
 return -ENOMEM;
}
static void __exit observe_exit(void) { debugfs_remove_recursive(directory); }
module_init(observe_init);
module_exit(observe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read exact failed physical FQ owner without changing it");
