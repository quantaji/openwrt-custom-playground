// SPDX-License-Identifier: GPL-2.0-only
/* Exact live 69fe failed BF diagnostic: continue its overdue CPU event.
 * No firmware instruction/timer/lock store, no packet replay and no pass repair. */
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/qdx_diag_bf.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include "qdx.h"
#include "offsets.h"

#define WAIT_MS 3000
#define OUTER_TAG 0x6d040000U
#define PRIVATE_TAG 0x6d050000U
struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
struct recovery_packet { struct sk_buff *skb; u8 expected[64]; u32 id; };
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct recovery_packet) == 80);
static_assert(sizeof(struct qdx_diag_bf_cycle) == REC_cycle_state_SIZE);
static_assert(sizeof(struct qdx_diag_fq_view) == REC_owned_view_SIZE);
static_assert(sizeof(struct qdx_diag_bf_multigroup_update) == REC_multi_update_SIZE);
#define SLOT(type, name) ((type *)(REC_##name##_BASE + REC_##name))
#define FLAG(name) (*SLOT(bool, name))
#define WORD(name) (*SLOT(u32, name))
#define QUAD(name) (*SLOT(u64, name))
#define POINTER(type, name) (*SLOT(type *, name))
static unsigned long text, data, bss;
static struct module *original, *driver;
static struct dentry *directory;
static DEFINE_MUTEX(recovery_lock);
static bool allow_writes;
module_param(allow_writes, bool, 0400);
static u32 stage, expected_order[30], seen_mask[2], returned_count;
static s32 expected_deficit[2][2], actual_deficit[2][2];
static s64 expected_credit, activation_credit, service_bound[2];
static u64 activation_reference, original_due, event_clock, late_units;
static bool imported, detached, activated, cleared, opened, completed, consequence, observed, self_pinned;
static int result;
static u8 before_account[2][312], before_group[2][232], after_group[2][232];
static struct qdx_diag_bf_cycle quiet;
static int (*read_owned)(enum qdx_diag_fq_range, unsigned int, unsigned int, void *);
static int (*snapshot)(unsigned int);
static int (*publish)(void);
static int (*sample_clock)(void);
static int (*command)(u32,u32,u32);
static int (*table_get)(struct qdx_service *,struct qdx_dma *,const struct qdx_owner *,dma_addr_t *);
static void (*table_put)(struct qdx_dma *);
static bool (*table_matches)(struct qdx_dma *,const u8 *);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);

static unsigned long section_address(struct module *module, const char *name)
{
 struct recovery_sections *sections = (void *)module->sect_attrs;
 const struct bin_attribute *const *entry; unsigned int i;
 if (!sections || !sections->grp.bin_attrs) return 0;
 entry = sections->grp.bin_attrs;
 for (i = 0; i < 64 && entry[i]; i++)
  if (!strcmp(entry[i]->attr.name, name)) return (unsigned long)entry[i]->private;
 return 0;
}
static int resolve_function(const char *name, unsigned long expected, void *destination)
{
 struct kprobe probe = { .symbol_name = name }; int error = register_kprobe(&probe);
 if (error) return error;
 if ((unsigned long)probe.addr != expected) error = -ESTALE;
 else *(void **)destination = (void *)probe.addr;
 unregister_kprobe(&probe); return error;
}
static int bind_original(void)
{
 static const u8 build_id[20] = {0x59,0x04,0xc4,0x25,0xbe,0x17,0x51,0xbd,0x5f,0x18,
  0x48,0xd4,0xae,0x35,0x29,0x7c,0x2c,0xb4,0xd8,0x21};
 struct kprobe finder = { .symbol_name = "find_module" };
 struct module *(*find_named)(const char *); unsigned long note, driver_text; int error;
 error = register_kprobe(&finder); if (error) return error;
 find_named = (void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock(); original = find_named("qdx_mirror_state_diag"); driver = find_named("qdx_drv");
 if (original && !try_module_get(original)) original = NULL;
 if (driver && !try_module_get(driver)) driver = NULL;
 rcu_read_unlock();
 if (!original || !driver) return -ENOENT;
 if (original->state != MODULE_STATE_LIVE || driver->state != MODULE_STATE_LIVE) return -ESTALE;
 text=section_address(original,".text");data=section_address(original,".data");bss=section_address(original,".bss");
 note=section_address(original,".note.gnu.build-id");driver_text=section_address(driver,".text");
 if (!text || !data || !bss || !note || !driver_text ||
     section_address(original,".gnu.linkonce.this_module") != (unsigned long)original ||
     !within_module(note,original) || !within_module(note+35,original) ||
     get_unaligned_le32((void *)note)!=4 || get_unaligned_le32((void *)(note+4))!=20 ||
     get_unaligned_le32((void *)(note+8))!=3 || memcmp((void *)(note+12),"GNU",4) ||
     memcmp((void *)(note+16),build_id,20)) return -ESTALE;
 /* Complete generated access list: every SLOT, FLAG, WORD, QUAD and POINTER. */
#include "bounds.inc"
 error=resolve_function("qdx_mirror_state_diag:state_owned_read",text+REC_state_owned_read,&read_owned);
 if (!error) error=resolve_function("qdx_mirror_state_diag:state_cycle_snapshot",text+REC_state_cycle_snapshot,&snapshot);
 if (!error) error=resolve_function("qdx_mirror_state_diag:state_multi_publish",text+REC_state_multi_publish,&publish);
 if (!error) error=resolve_function("qdx_mirror_state_diag:state_multi_clock",text+REC_state_multi_clock,&sample_clock);
 if (!error) error=resolve_function("qdx_mirror_state_diag:state_cycle_command",text+REC_state_cycle_command,&command);
 /* d512 packaged module has no BuildID. Root verifies its actual artifact;
  * these exact .text offsets are from that artifact's own symbol table. */
 if (!error) error=resolve_function("qdx_drv:qdx_diag_fq_table_get",driver_text+0x3eac,&table_get);
 if (!error) error=resolve_function("qdx_drv:qdx_diag_fq_table_put",driver_text+0x4050,&table_put);
 if (!error) error=resolve_function("qdx_drv:qdx_diag_fq_table_matches",driver_text+0x4080,&table_matches);
 return error;
}
/* Retry only the reader's explicit transient consistency refusal. Firmware
 * commands and mutation are never retried by this observation loop. */
static int read_quiet(unsigned int sample)
{
 unsigned long deadline=jiffies+msecs_to_jiffies(WAIT_MS); int error;
 do {
  error=snapshot(sample);
  if (error!=-EAGAIN) return error;
  if (POINTER(struct qdx_packet_op,operation) || POINTER(struct qdx_request,request) ||
      POINTER(struct qdx_request,bf_request)) return -EINPROGRESS;
  usleep_range(500,1000);
 } while (time_before(jiffies,deadline));
 return -ETIMEDOUT;
}
static int owner_ready(void)
{
 struct recovery_packet *packets=SLOT(struct recovery_packet,cycle_hold); unsigned int i;
 if (!FLAG(pinned)||FLAG(fault)||FLAG(closed)||!FLAG(bf_multigroup_test)||!FLAG(cycle_bound)||
     !FLAG(cycle_started)||!FLAG(cycle_cpu)||FLAG(cycle_closed)||FLAG(cycle_allocator_window)||
     !FLAG(multi_started)||!FLAG(multi_cut)||!FLAG(multi_evacuated)||!FLAG(multi_deposited)||!FLAG(multi_activated)||
     WORD(cycle_allocated)!=0x1ff||(WORD(cycle_links)&7)!=7||(WORD(cycle_links)&BIT(5))||
     WORD(multi_cpu_selected)!=2||WORD(multi_cpu_mask)!=3||WORD(multi_accepted)!=14||!FLAG(multi_op_closed)||
     WORD(cycle_hold_returned)!=16||WORD(cycle_hold_valid)!=16||WORD(cycle_hold_disposed)||
     POINTER(struct qdx_request,request)||POINTER(struct qdx_request,bf_request)||POINTER(struct qdx_packet_op,operation)||
     !POINTER(struct qdx_packet_op,probe_operation)||!POINTER(struct qdx_packet_op,multi_op)||
     !POINTER(struct qdx_dma,table)||!qdx_diag_fq_table_idle(POINTER(struct qdx_dma,table))) return -EPERM;
 for(i=0;i<2;i++) if(!packets[i].skb||packets[i].id!=i||packets[i].skb->len!=64||
   skb_is_nonlinear(packets[i].skb)||memcmp(packets[i].skb->data,packets[i].expected,64)) return -EBADMSG;
 return 0;
}
/* The existing checked publication authenticated every complete shared line.
 * Since then only this owned B-child DETACH/ATTACH ran. Re-read all owners after
 * its ACK. No queued callback, selector, producer or config writer remains.
 * This store only clears the inherited wait after a REAL positive activation.
 * Preserve driver arena lifetime and registered table borrow exactly as IO. */
static int clear_inherited_wait(void)
{
 struct qdx_diag_bf_cycle *c=SLOT(struct qdx_diag_bf_cycle,cycle_state);
 struct qdx_diag_fq_view *v=SLOT(struct qdx_diag_fq_view,owned_view);
 struct qdx_packet_op *op=POINTER(struct qdx_packet_op,probe_operation);
 struct qdx_core *core=op->endpoint->core; struct qdx *qdx=core->qdx;
 struct qdx_dma *region=POINTER(struct qdx_dma,table);
 struct qdx_endpoint *mirror=POINTER(struct qdx_endpoint,mirror);
 struct qdx_owner owner={.module=original,.object=SLOT(u8,rounds)};
 dma_addr_t table_address; unsigned long flags; u32 a=c->group_address[0],b=c->group_address[1],p=c->parent_address[0];
 unsigned int i; int error; bool admitted;
 if ((WORD(cycle_links)&0x3f)!=15||!imported||!activated||c->group_valid!=15||c->timer_valid!=15||c->parent_valid!=3||
     (a&31)!=12||b!=a+232||(b&31)!=20||c->group_address[3]!=b+232||
     (get_unaligned_le32(SLOT(u8,cycle_epoch))&1)||(get_unaligned_le32(SLOT(u8,cycle_epoch)+16)&1)) return -EPERM;
 for(i=0;i<4;i++) if((get_unaligned_le32(c->group[i])&1)||c->group[i][160]||
   (get_unaligned_le32(c->timer[i]+24)&2)) return -EBUSY;
 if(c->group[3][24]||c->group[3][228]||c->group[3][229]||get_unaligned_le32(c->group[3]+4)||
    get_unaligned_le32(c->group[3]+212)||!c->group[1][229]||!c->group[1][228]||
    get_unaligned_le32(c->group[1]+224)!=1||get_unaligned_le32(c->group[1]+4)!=p||
    get_unaligned_le32(c->parent[0]+196)!=2||get_unaligned_le32(c->parent[0]+172)!=a+172||
    get_unaligned_le32(c->parent[0]+176)!=b+172||get_unaligned_le32(c->parent[0]+180)!=a+188||
    get_unaligned_le32(c->parent[0]+184)!=b+188||activation_credit<=0) return -EBADMSG;
 if(core!=mirror->core||core->qdx!=mirror->service->qdx||!core->image||b<core->image_phys||b-core->image_phys>core->image_size||
    256>core->image_size-(b-core->image_phys)) return -ERANGE;
 spin_lock_irqsave(&qdx->io_admission,flags);
 admitted=!qdx->io_closing&&!atomic_read(&qdx->failure);
 if(admitted) atomic_inc(&qdx->io_callers);
 spin_unlock_irqrestore(&qdx->io_admission,flags);
 if(!admitted) return -ESHUTDOWN;
 error=table_get(mirror->service,region,&owner,&table_address);
 if(!error){
  if(!table_matches(region,v->table)) error=-ESTALE;
  else { writeb(0,core->image+b-core->image_phys+229);wmb();cleared=true; }
  table_put(region);
 }
 spin_lock_irqsave(&qdx->io_admission,flags);
 if(atomic_dec_and_test(&qdx->io_callers)) wake_up_all(&qdx->io_drained);
 spin_unlock_irqrestore(&qdx->io_admission,flags);
 return error;
}
/* Independent late-service oracle. Both full caps lie strictly between one
 * and two costs. Three preferred selections per group therefore occur before
 * pre-debit negativity removes it. CPU's two earlier B outputs are separate. */
static int expected_suffix(void)
{
 static const u32 fq[16]={0,8,1,2,3,9,10,4,5,6,11,12,7,13,14,15};
 u32 list[2][2]={{0,1},{0,1}},n[2]={2,2},used[2]={0,2},selected[2]={0,0};
 s32 d[2][2]={{64,0},{-64,0}};unsigned int out,r,g,k,i,j;
 for(out=0;out<30;out++){
  r=n[0]?0:1;if(!n[r]) return -EBADMSG;
  for(k=0;k<16;k++){g=list[r][0];if(d[g][r]>=0)break;d[g][r]+=128;
   if(n[r]==2){list[r][0]=list[r][1];list[r][1]=g;}}
  if(k==16||used[g]>=16)return -EBADMSG;
  expected_order[out]=g?0x100+used[g]:fq[used[g]];used[g]++;selected[g]++;d[g][r]-=64;
  for(i=0;i<2;i++) if(used[g]==16||(!i&&selected[g]>=3))
   for(j=0;j<n[i];j++)if(list[i][j]==g){if(j+1<n[i])list[i][j]=list[i][j+1];n[i]--;break;}
 }
 memcpy(expected_deficit,d,sizeof(d));return 0;
}
static int continue_late(void)
{
 struct qdx_diag_bf_cycle *c=SLOT(struct qdx_diag_bf_cycle,cycle_state);
 struct qdx_diag_bf_multigroup_update *u=SLOT(struct qdx_diag_bf_multigroup_update,multi_update);
 unsigned long deadline;u64 ref,old_ref,elapsed,cap,cost;unsigned int i,j;int error;
 /* Finish only an actual retained command matching this phase. */
 if(POINTER(struct qdx_request,bf_request)){
  u32 pending=WORD(bf_command_pending),tag=WORD(bf_tag_pending),child=WORD(bf_child_pending);
  bool expected=(!detached&&imported&&pending==6&&tag==c->group_tag[1]&&child==PRIVATE_TAG)||
   (!activated&&detached&&pending==5&&tag==c->group_tag[1]&&child==PRIVATE_TAG)||
   (!opened&&cleared&&pending==5&&tag==OUTER_TAG&&child==c->parent_tag[0])||
   (opened&&pending==6&&tag==OUTER_TAG&&child==c->parent_tag[0]);
  if(!expected)return -EINPROGRESS;
  error=command(pending,tag,child);if(error)return error;
  if(pending==5&&tag==OUTER_TAG){opened=true;stage=5;}
 }
 error=owner_ready();if(error)return error;
 if(observed)return result;
 if(!imported){
  if(FLAG(cycle_imported)||FLAG(cycle_event)||FLAG(cycle_service)||WORD(probe_returns)||WORD(multi_returned)||
     WORD(probe_disposed)||WORD(multi_disposed)||WORD(cycle_links)!=15||*SLOT(int,last_error)!=-EAGAIN) return -EPERM;
  error=sample_clock();if(!error)error=read_quiet(2);if(error)return error;
  original_due=QUAD(multi_initial_due);event_clock=QUAD(multi_clock);
  if(!original_due||event_clock<=original_due) return -ETIME;
  late_units=event_clock-original_due;
  /* Do not pretend the intended negative-event discriminator still holds. */
  memcpy(before_account,c->account,sizeof(before_account));
  if(!self_pinned){if(!try_module_get(THIS_MODULE))return -ENODEV;self_pinned=true;}
  error=publish();if(error){self_pinned=false;module_put(THIS_MODULE);return error;}
  imported=true;FLAG(cycle_imported)=true;WORD(cycle_stage)=5;stage=1;
 }
 if(!detached){
  if(WORD(cycle_links)&BIT(3)){error=command(6,c->group_tag[1],PRIVATE_TAG);if(error)return error;}
  detached=true;stage=2;
 }
 if(!activated){
  if(!(WORD(cycle_links)&BIT(3))){error=command(5,c->group_tag[1],PRIVATE_TAG);if(error)return error;}
  activated=true;stage=3;
 }
 if(!cleared){
  error=read_quiet(5);if(error)return error;
  activation_credit=(s64)get_unaligned_le64(c->account[1]+292);
  activation_reference=get_unaligned_le64(c->account[1]+300);
  old_ref=u->reference[1];cap=get_unaligned_le64(c->account[1]+284);
  if(activation_reference<old_ref||get_unaligned_le32(c->account[1]+272)||get_unaligned_le32(c->account[1]+280))return -ERANGE;
  elapsed=activation_reference-old_ref;
  if(elapsed>S64_MAX||check_add_overflow(u->credit[1],(s64)elapsed,&expected_credit))return -EOVERFLOW;
  expected_credit=min_t(s64,expected_credit,cap);
  if(expected_credit<=0||activation_credit!=expected_credit)return -EBADMSG;
  for(i=0;i<2;i++)for(j=0;j<2;j++)if((s32)get_unaligned_le32(c->group[i]+184+j*16)!=(j?0:i?-64:64))return -EBADMSG;
  if((s64)get_unaligned_le64(c->account[0]+292)!=u->credit[0]||get_unaligned_le64(c->account[0]+300)!=u->reference[0])return -EBADMSG;
  memcpy(before_group,c->group,sizeof(before_group));quiet=*c;
  error=clear_inherited_wait();if(error)return error;stage=4;
 }
 if(!opened){
  error=read_quiet(7);if(error)return error;
  if(c->group[1][229]||memcmp(c->account,quiet.account,sizeof(quiet.account)))return -EBADMSG;
  for(i=0;i<2;i++)for(j=0;j<232;j++)if(c->group[i][j]!=(i==1&&j==229?0:before_group[i][j]))return -EBADMSG;
  FLAG(multi_event_computed)=true;FLAG(multi_event_published)=true;FLAG(cycle_event)=true;
  QUAD(multi_next_due)=0;QUAD(cycle_event_ms)=event_clock;WORD(cycle_stage)=6;
  /* The positive event is complete: no inherited future deadline exists. */
  error=sample_clock();if(error)return error;ref=QUAD(multi_reference);
  for(i=0;i<2;i++){
   old_ref=get_unaligned_le64(c->account[i]+300);cap=get_unaligned_le64(c->account[i]+284);
   j=get_unaligned_le32(c->account[i]+268);if(j>=32||(64U>>j)>=32||ref<old_ref)return -ERANGE;
   cost=get_unaligned_le64(c->account[i]+12+8*(64U>>j));elapsed=ref-old_ref;
   if(!cost||cost>S64_MAX/2||elapsed>S64_MAX||check_add_overflow((s64)get_unaligned_le64(c->account[i]+292),(s64)elapsed,&service_bound[i]))return -ERANGE;
   service_bound[i]=min_t(s64,service_bound[i],cap);
   if(service_bound[i]<=(s64)cost||cap>=2*cost)return -ENODATA;
  }
  error=expected_suffix();if(error)return error;
  /* Journal precedes command only via acknowledged edge bits. Never replay packets. */
  FLAG(cycle_service)=true;WORD(cycle_stage)=7;
  if(!(WORD(cycle_links)&BIT(4))){error=command(5,OUTER_TAG,c->parent_tag[0]);if(error)return error;}
  opened=true;stage=5;
 }
 deadline=jiffies+msecs_to_jiffies(WAIT_MS);
 do{
  if(READ_ONCE(WORD(probe_returns))+READ_ONCE(WORD(probe_disposed))==16&&
     READ_ONCE(WORD(multi_returned))+READ_ONCE(WORD(multi_disposed))==14&&
     qdx_packet_op_drained(POINTER(struct qdx_packet_op,probe_operation))&&
     qdx_packet_op_drained(POINTER(struct qdx_packet_op,multi_op)))break;
  usleep_range(500,1000);
 }while(time_before(jiffies,deadline));
 if(WORD(probe_returns)+WORD(probe_disposed)!=16||WORD(multi_returned)+WORD(multi_disposed)!=14||
    !qdx_packet_op_drained(POINTER(struct qdx_packet_op,probe_operation))||!qdx_packet_op_drained(POINTER(struct qdx_packet_op,multi_op)))return -ETIMEDOUT;
 if(WORD(cycle_links)&BIT(4)){error=command(6,OUTER_TAG,c->parent_tag[0]);if(error)return error;}
 completed=true;stage=6;if(self_pinned){self_pinned=false;module_put(THIS_MODULE);}
 returned_count=WORD(cycle_service_count);
 if(WORD(probe_returns)!=16||WORD(probe_valid)!=16||WORD(probe_disposed)||WORD(multi_returned)!=14||WORD(multi_valid)!=14||WORD(multi_disposed)||returned_count!=30)return -EBADMSG;
 /* Queue table changed legitimately; refresh before authenticated empty reads. */
 error=read_owned((enum qdx_diag_fq_range)U32_MAX,0,144,SLOT(struct qdx_diag_fq_view,owned_view)->table);
 for(i=0;!error&&i<2;i++)error=read_owned(QDX_DIAG_BF_POOL_GROUP,SLOT(u32,cycle_group_slot)[i],232,after_group[i]);
 if(error)return error;
 seen_mask[0]=seen_mask[1]=0;
 for(i=0;i<30;i++){
  u32 id=SLOT(u32,cycle_service_order)[i],group=id>=0x100;
  u32 item=group?id-0x100:id;
  if(item>=16||(group&&item<2)||(seen_mask[group]&BIT(item)))return -EBADMSG;
  seen_mask[group]|=BIT(item);
  if(id!=expected_order[i])return -ENODATA;
 }
 for(i=0;i<2;i++)for(j=0;j<2;j++){
  actual_deficit[i][j]=(s32)get_unaligned_le32(after_group[i]+184+j*16);
  if(actual_deficit[i][j]!=expected_deficit[i][j])return -ENODATA;
 }
 if(QUAD(cycle_service_last_ns)<QUAD(cycle_service_first_ns)||
    QUAD(cycle_service_last_ns)-QUAD(cycle_service_first_ns)>=100*NSEC_PER_MSEC)return -ENODATA;
 consequence=true;observed=true;stage=7;
 /* Original last_error, cycle_result and cycle_oracle_valid are never changed.
  * Root next runs original cycle-close and normal restore; CPU B0/B1 remain. */
 return 0;
}
static ssize_t recovery_control_write(struct file *file,const char __user *buffer,size_t count,loff_t *position)
{
 char cmd[16];int error;
 if(!allow_writes)return -EPERM;
 if(!count||count>=sizeof(cmd))return -EINVAL;
 if(copy_from_user(cmd,buffer,count))return -EFAULT;
 cmd[count]=0;strim(cmd);if(strcmp(cmd,"continue"))return -EINVAL;
 mutex_lock(&recovery_lock);mutex_lock(SLOT(struct mutex,state_lock));
 error=continue_late();result=error;
 mutex_unlock(SLOT(struct mutex,state_lock));mutex_unlock(&recovery_lock);
 return error?:count;
}
static const struct file_operations recovery_control_fops={.owner=THIS_MODULE,.write=recovery_control_write};
static int recovery_status_show(struct seq_file *seq,void *unused)
{
 unsigned int i;mutex_lock(&recovery_lock);
 seq_printf(seq,"stage=%u result=%d imported=%u detached=%u activated=%u cleared=%u opened=%u completed=%u consequence=%u original_failed=1\n",stage,result,imported,detached,activated,cleared,opened,completed,consequence);
 seq_printf(seq,"original_due=%llu event_clock=%llu late_units=%llu activation_credit=%lld expected_credit=%lld activation_reference=%llu returned=%u mask_a=%x mask_b=%x\n",original_due,event_clock,late_units,activation_credit,expected_credit,activation_reference,returned_count,seen_mask[0],seen_mask[1]);
 for(i=0;i<2;i++)seq_printf(seq,"group=%u service_bound=%lld expected_deficit=%d,%d actual_deficit=%d,%d before=%232phN after=%232phN\n",i,service_bound[i],expected_deficit[i][0],expected_deficit[i][1],actual_deficit[i][0],actual_deficit[i][1],before_group[i],after_group[i]);
 seq_puts(seq,"expected_order=");for(i=0;i<30;i++)seq_printf(seq,"%s%x",i?",":"",expected_order[i]);seq_putc(seq,'\n');
 mutex_unlock(&recovery_lock);return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 struct dentry *entry;int error;
 if(!allow_writes)return -EPERM;
 error=bind_original();if(error)goto fail;
 directory=debugfs_create_dir("qdx_bf_late_recovery",NULL);
 if(IS_ERR_OR_NULL(directory)){error=-ENOMEM;goto fail;}
 entry=debugfs_create_file("control",0200,directory,NULL,&recovery_control_fops);
 if(IS_ERR_OR_NULL(entry)){error=-ENOMEM;goto remove;}
 entry=debugfs_create_file("status",0400,directory,NULL,&recovery_status_fops);
 if(IS_ERR_OR_NULL(entry)){error=-ENOMEM;goto remove;}
 return 0;
remove:debugfs_remove_recursive(directory);
fail:if(driver)module_put(driver);if(original)module_put(original);return error;
}
static void __exit recovery_exit(void)
{
 debugfs_remove_recursive(directory);module_put(driver);module_put(original);
}
module_init(recovery_init);module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exact failed BF late-event continuation; preserves original failure and real packet owners");
