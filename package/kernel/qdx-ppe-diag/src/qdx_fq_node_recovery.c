// SPDX-License-Identifier: GPL-2.0-only
/* One bounded repair for frozen mirror module ELF116e0362. No address input. */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_fq.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>
#include "qdx_fq_node_recovery_offsets.h"

extern bool qdx_diag_fq_table_idle(struct qdx_dma *region);

/* Actual Linux6.18.44 kernel/module/sysfs.c layout, not an ELF guess. */
struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
/* Exact original frozen source; build-time size guards the sole accessed tail. */
struct recovery_owned {
 struct completion original_done, clone_done;
 bool submitted, original_valid, clone_valid;
 u32 originals, clones, length, kind, index, clone_data_mod4;
 u64 elapsed_ns;
 u8 bytes[QDX_DIAG_FQ_NODE_BYTES];
 struct sk_buff *payload;
};
static_assert(sizeof(struct recovery_owned) == 392);
static_assert(sizeof(struct qdx_diag_fq_view) == 3056);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct module) == 1216);

static bool allow_writes;
module_param(allow_writes, bool, 0400);
static bool attempted, repaired, node_written;
static int result;
static u32 actual_node, validated_payloads, before_words[8], after_words[8];
static struct dentry *directory;
static const u16 word_offsets[] = { 224, 228, 232, 236, 240, 252, 256, 260 };
static const u8 expected_build_id[20] = {
 0xec,0x1e,0x1e,0x5d,0xcd,0x0e,0x57,0x9a,0x85,0xc2,
 0x3a,0xa4,0x61,0x11,0x04,0x79,0xb2,0xcb,0xda,0x8d
};

static unsigned long recovery_section(struct module *module, const char *name)
{
 struct recovery_sections *sections = (void *)module->sect_attrs;
 const struct bin_attribute *const *entry;
 unsigned int i;

 if (!sections || !sections->grp.bin_attrs)
  return 0;
 entry = sections->grp.bin_attrs;
 for (i = 0; i < 64 && entry[i]; i++)
  if (!strcmp(entry[i]->attr.name, name))
   return (unsigned long)entry[i]->private;
 return 0;
}

#define SLOT(type, name) ((type *)(bss + REC_##name))
#define FLAG(name) (*SLOT(bool, name))
#define WORD(name) (*SLOT(u32, name))
#define OBJECT(type, name) (*SLOT(type *, name))

static int recovery_run(void)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe reader = { .symbol_name = "qdx_mirror_state_diag:state_owned_read" };
 struct module *(*find_named)(const char *name);
 int (*read_owned)(enum qdx_diag_fq_range, unsigned int, unsigned int, void *);
 struct module *module;
 struct mutex *lock;
 struct qdx_diag_fq_view *view;
 struct recovery_owned *owned;
 struct sk_buff **prefix, *copy;
 void __iomem *mapping = NULL;
 unsigned long text, data, bss, note, this_section;
 u8 node_before[280], node_after[280], node_expected[280], actual_table[144];
 u32 *values, address, id, begin, end;
 unsigned int i;
 int error;

 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr;
 unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_mirror_state_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_mirror_state_diag")) {
  error = -ESTALE; goto release;
 }
 text = recovery_section(module, ".text");
 data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss");
 note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x4957, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0x77, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x2541, module, MOD_DATA) ||
     !within_module(note, module) || !within_module(note + 35, module)) {
  error = -ERANGE; goto release;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), expected_build_id, sizeof(expected_build_id))) {
  error = -ESTALE; goto release;
 }
 error = register_kprobe(&reader);
 if (error) goto release;
 read_owned = (void *)reader.addr;
 unregister_kprobe(&reader);
 if ((unsigned long)read_owned != text + 0xd0c) { error = -ESTALE; goto release; }
 lock = (void *)(data + REC_state_lock);
 mutex_lock(lock);
 attempted = true;
 view = (void *)(bss + REC_owned_view);
 owned = (void *)(bss + REC_owned);
 prefix = (void *)(bss + REC_owned_payload);
 values = (void *)(bss + REC_adopt_node_values);
 if (!FLAG(pinned) || FLAG(closed) || FLAG(fault) || FLAG(probe_started) ||
     !FLAG(probe_snapshot_valid) || !FLAG(adopt_cpu) || !FLAG(adopt_rebuild_started) ||
     FLAG(adopt_retiring) || FLAG(adopt_imported) ||
     WORD(adopt_retired) != 16 || WORD(adopt_retirement_bad) ||
     WORD(adopt_accepted) != 14 || WORD(adopt_returns) || WORD(adopt_disposed) ||
     WORD(adopt_bad_owner) || WORD(probe_qlen) != 14 || WORD(probe_drops) ||
     *SLOT(int, last_error) != -EINVAL || OBJECT(struct qdx_request, request) ||
     OBJECT(struct qdx_packet_op, operation) || !OBJECT(struct qdx_dma, table) ||
     !OBJECT(struct qdx_packet_op, probe_operation) ||
     !qdx_diag_fq_table_idle(OBJECT(struct qdx_dma, table)) ||
     qdx_packet_op_drained(OBJECT(struct qdx_packet_op, probe_operation)) ||
     !view->node_valid || view->carrier_valid != 0x3fff || view->metadata_valid != 0x3fff ||
     owned->payload || !prefix[0] || !prefix[8] || prefix[0]->len != 64 || prefix[8]->len != 64 ||
     get_unaligned_le32(prefix[0]->data + 46) || get_unaligned_le32(prefix[8]->data + 46) != 8) {
  error = -EPERM; goto unlock;
 }
 for (i = 0; i < 16; i++)
  if (i != 0 && i != 8 && prefix[i]) { error = -EBADMSG; goto unlock; }
 address = WORD(table_address);
 actual_node = values[1] - 228;
 if (actual_node < 0x4027b62c || actual_node >= 0x4027b62c + 256 * 280 ||
     (actual_node - 0x4027b62c) % 280 ||
     (values[0] != address && values[0] != address + 72) ||
     values[1] != actual_node + 228 || values[2] != actual_node + 228 ||
     values[3] != address || values[4] != address + 72 || values[5] || values[6] != 2 || values[7] != 64) {
  error = -EBADMSG; goto unlock;
 }
 for (i = 0; i < 2; i++) {
  u8 *bin = view->table + i * 72;
  if (get_unaligned_le32(bin) != (i ? actual_node + 236 : address + 72) ||
      get_unaligned_le32(bin + 4) != (i ? address : actual_node + 236) ||
      get_unaligned_le32(bin + 8) != (i ? 128 : 192) ||
      get_unaligned_le32(bin + 12) != (u32)-64 || get_unaligned_le32(bin + 24) != 7 ||
      get_unaligned_le32(bin + 64) != 448 || bin[68] ||
      get_unaligned_le16(bin + 28) != 101 || get_unaligned_le16(bin + 30) != 37 ||
      !get_unaligned_le64(bin + 36)) { error = -EBADMSG; goto unlock; }
 }
 error = read_owned((enum qdx_diag_fq_range)U32_MAX, 0, 144, actual_table);
 if (error) goto unlock;
 if (memcmp(actual_table, view->table, 144)) { error = -ESTALE; goto unlock; }
 /* Each genuine copy revalidates all14 accepted owners, then the selected
  * cookie/generation/extent. Free only its newly created diagnostic clone.
  */
 for (i = 0; i < 14; i++) {
  error = read_owned(QDX_DIAG_FQ_PAYLOAD, i, 64, NULL);
  if (error) goto unlock;
  copy = owned->payload;
  id = i + 1 + (i >= 7);
  if (!copy || copy->len != 64 || get_unaligned_le32(copy->data + 42) != 0x46515354 ||
      get_unaligned_le32(copy->data + 46) != id) { error = -EBADMSG; goto unlock; }
  owned->payload = NULL;
  dev_kfree_skb(copy);
  validated_payloads++;
 }
 /* The last node MIRROR is the real cache-release predecessor of writes. */
 error = read_owned(QDX_DIAG_FQ_NODE, 0, 280, node_before);
 if (error) goto unlock;
 if (memcmp(node_before, view->node, 280) || get_unaligned_le32(node_before) ||
     get_unaligned_le32(node_before + 4) || get_unaligned_le32(node_before + 8) != 1 ||
     get_unaligned_le32(node_before + 16) != 0x6d010000 || node_before[24] ||
     get_unaligned_le32(node_before + 220) != address ||
     get_unaligned_le16(node_before + 264) != 2 || get_unaligned_le16(node_before + 266) != 1 ||
     get_unaligned_le32(node_before + 260) != 64) { error = -ESTALE; goto unlock; }
 for (i = 0; i < ARRAY_SIZE(word_offsets); i++) {
  begin = (actual_node + word_offsets[i]) & ~31U;
  end = (actual_node + word_offsets[i] + 3) | 31U;
  if (begin < actual_node || end >= actual_node + 280) { error = -EXDEV; goto unlock; }
  before_words[i] = get_unaligned_le32(node_before + word_offsets[i]);
 }
 memcpy(node_expected, node_before, sizeof(node_expected));
 mapping = ioremap(actual_node, 280);
 if (!mapping) { error = -ENOMEM; goto unlock; }
 for (i = 0; i < ARRAY_SIZE(word_offsets); i++) {
  writel(values[i], mapping + word_offsets[i]);
  put_unaligned_le32(values[i], node_expected + word_offsets[i]);
 }
 wmb();
 node_written = true;
 error = read_owned(QDX_DIAG_FQ_NODE, 0, 280, node_after);
 if (error) goto unlock;
 for (i = 0; i < ARRAY_SIZE(word_offsets); i++)
  after_words[i] = get_unaligned_le32(node_after + word_offsets[i]);
 if (memcmp(node_after, node_expected, sizeof(node_after))) { error = -EIO; goto unlock; }
 error = read_owned((enum qdx_diag_fq_range)U32_MAX, 0, 144, actual_table);
 if (error) goto unlock;
 if (memcmp(actual_table, view->table, 144)) { error = -EIO; goto unlock; }
 memcpy(view->node, node_after, 280);
 memcpy((void *)(bss + REC_adopt_after), actual_table, 144);
 FLAG(adopt_imported) = true;
 *SLOT(int, last_error) = 0;
 repaired = true;
 error = 0;
unlock:
 if (mapping) iounmap(mapping);
 mutex_unlock(lock);
release:
 module_put(module);
 return error;
}

static int recovery_status_show(struct seq_file *seq, void *unused)
{
 unsigned int i;
 seq_printf(seq, "allow_writes=%u attempted=%u repaired=%u node_written=%u result=%d node=%08x validated_payloads=%u\n",
  allow_writes, attempted, repaired, node_written, result, actual_node, validated_payloads);
 for (i = 0; i < ARRAY_SIZE(word_offsets); i++)
  seq_printf(seq, "offset=%u before=%08x after=%08x\n", word_offsets[i], before_words[i], after_words[i]);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);

static int __init recovery_init(void)
{
 if (!allow_writes) return -EPERM;
 directory = debugfs_create_dir("qdx_fq_node_recovery", NULL);
 debugfs_create_file("status", 0400, directory, NULL, &recovery_status_fops);
 result = recovery_run();
 pr_info("qdx_fq_node_recovery: result=%d wrote=%u repaired=%u payloads=%u\n",
  result, node_written, repaired, validated_payloads);
 /* Preserve the diagnostic result even on failure. No purge or ROOT call. */
 return 0;
}
static void __exit recovery_exit(void) { debugfs_remove_recursive(directory); }
module_init(recovery_init);
module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded recovery of frozen finite FQ max-packet guard failure");
