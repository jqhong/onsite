#ifndef IMEE
#define IMEE
#include <linux/list.h>
/* Jiaqi */
// #include <linux/kvm_types.h>
/* /Jiaqi */
#define DBG(fmt, ...) \
    do {printk ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

/*
#define DBG(fmt, ...) 
*/
// #define DBG(fmt, ...) 

#define ERR(fmt, ...) \
    do {printk ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

// struct arg_blk
// {
//     unsigned long vcpu_fd;
//     unsigned long syscall_flag;
//     unsigned long rip;
//     unsigned long rsp;
//     unsigned long rax;
//     unsigned long rdi;
//     unsigned long rsi;
//     unsigned long rdx;
//     unsigned long r10;
//     unsigned long r8;
//     unsigned long r9;
//     unsigned long r11;
//     unsigned long rcx;
//     unsigned long ret_rax;
//     unsigned long sstub_entry;
//     unsigned long hard_cr3;
// };
// /* Jiaqi */
// // extern struct arg_blk* imee_arg;
// extern struct arg_blk imee_arg;

struct arg_blk
{
    int instrum_flag;
    int pl_switch;
    unsigned long exit_gate_addr;
    unsigned long syscall_gate_addr;
    unsigned long syscall_gate_pa;
    unsigned long t_idt_va;
    unsigned long t_gdt_va;
    unsigned long t_tss_va;//2 tss pages
    unsigned long t_idt_pa;
    unsigned long t_gdt_pa;
    unsigned long t_tss_pa;
    unsigned long t_tss1_pa;
    unsigned long t_tss2_pa;
    unsigned long stack_addr;//0x2c0 from tss + int 3 stack + data
    unsigned long root_pt_addr;
    unsigned long shar_va;
    unsigned long shar_pa;
    unsigned long ana_t_tss_va;
    unsigned long ana_t_tss_pa;
    unsigned long ana_t_gdt_va;
    unsigned long ana_t_gdt_pa;
    unsigned long ana_t_idt_va;
    unsigned long ana_t_idt_pa;
    unsigned long ana_pf_c_page;
    unsigned long ana_pf_stack;
    unsigned long vcpu_fd;
    unsigned long syscall_flag;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rax;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
    unsigned long rcx;
    unsigned long ret_rax;
    unsigned long sstub_entry;
    unsigned long hard_cr3;
};
/* Jiaqi */
// extern struct arg_blk* imee_arg;
extern struct arg_blk imee_arg;

//used to pass target thread's register context between hyp and analyzer. 
struct shar_arg
{
    volatile unsigned long flag;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
    unsigned long r10;
    unsigned long rax;
    unsigned long eflags;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    // unsigned long long xmm0;
    // unsigned long long xmm1;
    // unsigned long long xmm2;
    // unsigned long long xmm3;
    // unsigned long long xmm4;
    // unsigned long long xmm5;
    // unsigned long long xmm6;
    // unsigned long long xmm7;
    unsigned long fs_base;
    unsigned long gs_base;
    unsigned long msr_kernel_gs_base;
    unsigned long gdt;
    unsigned long idt;
    unsigned long tss_base;
    unsigned long tss_pg_off;
    unsigned long g_syscall_entry;
    unsigned long pf_entry;
    unsigned long int3_entry;
    unsigned long cr0;
    unsigned long cr2;
    unsigned long cr3;
    unsigned long cr4;
    unsigned long efer;
    unsigned long apic_base_addr;
    unsigned long apic_access_addr;
    unsigned long io_bitmap_a_addr;
    unsigned long io_bitmap_b_addr;
    unsigned long msr_bitmap_addr;
    unsigned long tsc_offset;
    unsigned long exit_reason;
    unsigned long exit_qualification;
    unsigned long inst_len;
    unsigned long event_flag;
    unsigned long entry_intr_info;
    unsigned long user_flag;
    volatile unsigned long guest_timeout_flag;
    volatile unsigned long exit_wrong_flag;
    volatile unsigned long cross_page_flag;
};
// extern struct shar_arg* ei_shar_arg;

extern unsigned long host_syscall_entry;
extern unsigned long host_pf_entry;
extern unsigned long guest_syscall_entry;
extern unsigned long onsite_syscall_entry;
extern int vmc_idx;
struct sig_record{
    void* sig_handler;
    // int index;
    // int flag;
};
// struct sig_record sig_array[64];
// EXPORT_SYMBOL_GPL (sig_array);
extern struct sig_record sig_array[64];

struct gpa_hpa {
    unsigned long gpa;
    unsigned long hpa;
};

struct pt_mapping
{
    int lv;  // the level which the entry exits
    ulong e; // the paging structure entry
};

typedef struct introspection_context
{
    struct kvm* kvm;
    struct kvm_vcpu* target_vcpu;
    struct task_struct* task;
    ulong visited;

    ulong eptp;
    struct list_head pt_page; // pt pages of EPT
    struct list_head pd_page; // pd may contain large(2MB) entries 
    struct list_head non_leaf_page; // pdpt & pml4 pages of EPT

    ulong s_eptp;
    struct list_head s_pt_page;
    struct list_head s_pd_page;
    struct list_head s_non_leaf_page;
    // u64 cr3;//onsite cr3
    u64 t_cr3;
    u64 o_cr3;

    struct list_head node; // linked to global list

} intro_ctx_t;


extern intro_ctx_t* current_target;

// #define PD_GPA (0xF0000000U)
// #define PT_GPA_EXEC (0xF0001000U)
// #define PT_GPA_DATA (0xF0002000U)
// #define CODE_GPA (0xF0003000U)
// #define DATA_GPA (0xF0004000U)


// #define SCAN_ALL 1
// #define SCAN_ONE 2
// extern int imee_scan_mode;

extern volatile struct kvm_vcpu* imee_vcpu;
// extern int enable_notifier;
extern volatile int imee_pid;
extern spinlock_t sync_lock;
// extern volatile unsigned char go_flg;
// extern ulong code_hpa, data_hpa;
/* change type from u32 to unsigned long by Jiaqi */
// extern volatile u32 last_cr3;
// extern volatile u32 last_rip, last_rsp;
extern volatile unsigned long last_cr3;
extern volatile unsigned long last_rip, last_rsp;
extern volatile unsigned long onsite_cr3;

extern struct kvm_sregs imee_sregs;

volatile extern int exit_flg;
volatile extern unsigned long switched_cr3;

int remap_gpa (intro_ctx_t* ctx, ulong gpa);

void copy_leaf_ept (intro_ctx_t* ctx, struct kvm_arch* arch);
intro_ctx_t* kvm_to_ctx (struct kvm* target);
void switch_intro_ctx (intro_ctx_t* next, struct kvm_vcpu* vcpu);
u64 make_imee_ept (intro_ctx_t* ctx);
int start_guest_intercept (struct kvm_vcpu *vcpu);
int vcpu_entry(void);
int vcpu_reentry(void);
int adjust_dota_context (struct kvm_vcpu *vcpu);
struct kvm_vcpu* pick_cpu (struct kvm* target_kvm);

int adjust_ept_entry (intro_ctx_t* ctx, unsigned long gpa, unsigned long new_pa, int permission);
u64 get_epte_onsite (intro_ctx_t* ctx, u64 gpa);

extern struct desc_ptr imee_idt, imee_gdt;
extern struct kvm_segment imee_tr;
extern ulong code_entry;
extern int trial_run;

extern intro_ctx_t* cur_ctx;

// void change_imee_ept (ulong hva, pte_t pte);
// void invalidate_imee_ept (ulong gpa);
int kvm_imee_stop (struct kvm_vcpu* vcpu);
int kvm_imee_get_guest_context (struct kvm_vcpu *vcpu, void* argp);
// long kvm_imee_get_guest_context (struct kvm_vcpu *vcpu);

// #define UK_OFFSET 0xffff6a8000000000UL
// #define UK_OFFSET (kernel_idx-user_idx)*2^39+0xffff000000000000
extern unsigned long UK_OFFSET;
// #define user_start 0x7ff000000000UL
// #define user_end 0x7ffff8000000UL
#define user_start 0x7f8000000000UL
#define user_end 0x7fffffffffffUL
// the address of onsite wrapper
// #define onsite_wrapper_addr 0x7ff020300000UL
#define onsite_wrapper_addr 0x7f9000300000UL
// the address of dummy_sighandler
// #define dummy_handler_addr 0x7ff020600000UL
#define dummy_handler_addr 0x7f9000600000UL
// the address of sigflag in dummy_sighandler
// #define user_sigflag_addr 0x7ff020804000UL
#define user_sigflag_addr 0x7f9000804000UL

// #define sstub_addr 0x7ff020900000UL
/* to install descriptor tables and debug handler */ 
// #define debug_handler_addr 0x7ff020900000UL
#define gate_addr 0x7f9000900000UL
#define gate_data_num 0xa000 //first part: 1 IDT page + 1 GDT page + 2 TSS page + 1 writable data page; second part: 1 page for root PT + 1 page for shar_mem; third part: three VA pages for the analyzer to access the tss_struct, GDT, and IDT in the s_ept.// The second and third part are not mapped in t-EPT
#define syscall_page_addr 0x7f900090b000UL
// #define kn_shar_addr 0x7f900090c000UL

// #define pf_handler_addr 0x7ff02090d000UL
#define onsite_pf_addr 0x7f900090d000UL//its data page locates at +0x1000
/* / */

#endif

