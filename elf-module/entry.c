#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/binfmts.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <asm/current.h>
#include <asm/desc.h>
#include <linux/mman.h>

#include "imee.h"

extern unsigned long UK_OFFSET;
extern struct arg_blk imee_arg;
extern unsigned long host_syscall_entry;

int my_load_elf_binary(struct linux_binprm *bprm);

void* old_loader_start;

unsigned char inst_stub[5];
unsigned char old_bytes[5];

void old_loader_addr_init (void)
{
    old_loader_start = (void*) kallsyms_lookup_name("load_elf_binary");
    return;
}
// 
void print_bytes (void* p, int len)
{
    int i = 0;
    for ( ; i < len; i ++)
    {
        unsigned char* pp = (unsigned char*) p;
        printk ("%02x ", pp[i]);
    }
    printk ("\n");
    return;
}

void clear_WP_bit (void)
{
    unsigned long cr0;

    asm volatile ("movq %%cr0, %0;":"=r"(cr0)::);
    printk (KERN_ERR "changing CR0 from %X\n", cr0);
    cr0 &= ~(1 << 16);
    printk (KERN_ERR "to %X, WP_bit cleared.\n", cr0);
    asm volatile ("movq %0, %%cr0;"::"r"(cr0):);
}

void set_WP_bit (void)
{
    unsigned long cr0;

    asm volatile ("movq %%cr0, %0;":"=r"(cr0)::);
    printk (KERN_ERR "changing CR0 from %X\n", cr0);
    cr0 |= (1 << 16);
    printk (KERN_ERR "to %X, WP_bit set\n", cr0);
    asm volatile ("movq %0, %%cr0;"::"r"(cr0):);
}

int proc_filter (struct linux_binprm *bprm)
{
    // printk ("invoked. comm : %s. \n", current->comm);
    if (strstr(bprm->filename, "testtest"))
    {
        // printk ("testtest process. \n");
        int ret = my_load_elf_binary(bprm);
        // unsigned long* temp_rsp;
        // asm volatile("movq %%rsp, %0; \n\t"
        //         :"=m"(temp_rsp)::);
        // int i =0;
        // for (i; i<40; i ++)
        // {
        //     printk ("rsp: %p, content: %lx. \n", temp_rsp, *temp_rsp);
        //     temp_rsp ++;
        // }
        return ret;
    }
    else
        return 1;
}

static void branch (void);
asm (" .text");
asm (" .type    branch, @function");
asm ("branch: \n");
asm ("pushfq \n");
asm ("pushq %rax \n");
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rbp \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("callq proc_filter \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rbp \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rdx \n");
asm ("popq %rcx \n");
asm ("popq %rbx \n");

asm ("cmp $0x0, %rax \n");
asm ("je 1f \n");

asm ("popq %rax \n");
asm ("popfq \n");
asm ("retq \n");

asm ("1: \n");
asm ("addq $0x18, %rsp \n");
asm ("retq \n");

void elf_mod (void)
{
    old_loader_addr_init ();
    printk ("old code: ");
    print_bytes (old_loader_start, 26);
    printk ("addr of my_load_elf_binary: %px\n", branch);

    unsigned long offset = ((char*) branch) - ((char*) old_loader_start + 5);
    printk ("offset: %lx\n", offset);
    // inst_stub[0] = 0xe9;
    inst_stub[0] = 0xe8;
    inst_stub[1] = (offset >> 0) & 0xFF;
    inst_stub[2] = (offset >> 8) & 0xFF;
    inst_stub[3] = (offset >> 16) & 0xFF;
    inst_stub[4] = (offset >> 24) & 0xFF;
    printk ("inst_stub: ");
    print_bytes (inst_stub, 5);

    memcpy (old_bytes, old_loader_start, 5);
    memcpy (old_loader_start, inst_stub, 5);
    return;
}

int vcpu_entry(void);
int vcpu_reentry(void);
//?during interrupt, whehter swapgs by hardware? if not, swapgs before jump to
//system_call entry?
void syscall_bounce (void)
{
    unsigned long syscall_idx;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
    unsigned long ret_addr;
    unsigned long save_eflags;
    unsigned long rsp;
    syscall_idx = imee_arg.rax;
    arg1 = imee_arg.rdi;
    arg2 = imee_arg.rsi;
    arg3 = imee_arg.rdx;
    arg4 = imee_arg.r10;
    arg5 = imee_arg.r8;
    arg6 = imee_arg.r9;
    ret_addr = imee_arg.rip;
    save_eflags = imee_arg.r11;
    rsp = imee_arg.rsp;

    /* just for syscall performance testing */
    // if (syscall_idx == 0x27)
    // {
    //     unsigned long long t1;
    //     t1 = rdtsc();
    //     printk ("just before getpid handler, t1: %llx, t0: %llx, t1-t0: %d\n", t1, arg2, t1-arg2);
    // }
    /* / */
    /* TODO: it is likely issued by libc/ld in its initialization stage, since
     * the mmap addr is NULL, kernel is not assured to create the map within
     * the designed 512GB range, so I use this ugly solution ..... */
    if (syscall_idx == 9 && arg1 == NULL)
    {
        if (arg2 == 0x2000)
        {
            printk ("---------------------it is a 0x2000 sized non-fixed mmap. \n");
            arg1 = 0x7ffff7ff9000;
            arg4 |= MAP_FIXED;
        }
        else
        {
            printk ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!unexpected non-fixed mmap, terminate process. \n");
            syscall_idx = 231;
            arg1 = 0;
        }
    }
    // DBG ("host_syscall_entry in syscall_bounce: %lx. \n", host_syscall_entry);

    asm volatile ("movq %0, %%rax; \n\t"
            "movq %1, %%rdi; \n\t"
            "movq %2, %%rsi; \n\t"
            "movq %3, %%rdx; \n\t"
            "movq %4, %%r10; \n\t"
            "movq %5, %%r8; \n\t"
            "movq %6, %%r9; \n\t"
            "movq %7, %%rcx; \n\t"
            "movq %8, %%r11; \n\t"
            "pushf; \n\t"
            "popq %%rbx; \n\t"
            "and $0xc8ff, %%rbx; \n\t"
            "pushq %%rbx; \n\t"
            "popf; \n\t"
            "movq %10, %%rbx; \n\t"
            "movq %9, %%rsp; \n\t"
            "swapgs; \n\t"//switch gs to user space gs before jump to system call entry 
            // "movq $0xffffffff817142b0, %%rbx; \n\t"
            "jmpq *%%rbx; \n\t"
            ::"m"(syscall_idx),"m"(arg1),"m"(arg2),"m"(arg3),"m"(arg4),"m"(arg5),"m"(arg6),"m"(ret_addr),"m"(save_eflags),"m"(rsp), "m"(host_syscall_entry):"%rax","%rdi","%rsi","%rdx","%r10","%r8","%r9","%rcx","%r11","%rsp");
    return;
}

static void clear_bp (void)
{
    asm volatile ("pushq %%rax; \n\t"
            "movq $0x0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq $0x400, %%rax; \n\t"
            "movq %%rax, %%DR7; \n\t"
            "movq $0xfffe0ff0, %%rax; \n\t"
            "movq %%rax, %%DR6; \n\t"
            "popq %%rax; \n\t"
            :::"%rax");
    return;
}

// static void read_bp (void)
// {
//     unsigned long dr7, dr0;
//     asm volatile ("pushq %%rax; \n\t"
//             "movq %%DR7, %%rax; \n\t"
//             "movq %%rax, %0; \n\t"
//             "movq %%DR0, %%rax; \n\t"
//             "movq %%rax, %1; \n\t"
//             "popq %%rax; \n\t"
//             :"=m"(dr7), "=m"(dr0)::"%rax");
//     DBG ("initial value for DR7: %lx, DR0: %lx\n", dr7, dr0);
//     return;
// }

void noinline set_bp (unsigned long dr0, unsigned long dr7)
{
    asm volatile ("pushq %%rax; \n\t"
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq %1, %%rax; \n\t"
            "movq %%rax, %%DR7; \n\t"
            "popq %%rax; \n\t"
            ::"m"(dr0), "m"(dr7):"%rax");
    // printk ("now dr0: %lx, dr7: %lx\n", dr0, dr7);
    return 0;
}

void enter_vcpu (unsigned long arg)
{
    int r;
    unsigned long dr_s, dr_z;
    clear_bp();
    // DBG ("bp triggered, rax: %lx \n", arg);
    if (strstr(current->comm, "testtest"))
    {
        if (imee_arg.syscall_flag == 0)//this is return from execve
        {
            r = vcpu_entry();
            printk ("return from first time vcpu enter, r = %d\n", r);
            if (r == -2)//this is vmcall due to syscall in dota mode
            {
                dr_s = 0x401;
                dr_z = imee_arg.rip;
                set_bp(dr_z, dr_s);
                syscall_bounce ();
            }
            else 
            {
                printk ("onsite process should exit due to unexpected error, returned r: %d from vcpu_entry \n", r);
                /* sth went wrong in oasis life cycle, free oasis related objects and issue exit syscall directly? */
                imee_arg.rax = 231;
                imee_arg.rdi = 0;
                syscall_bounce ();
                // arg2 = imee_arg.rsi;
                // arg3 = imee_arg.rdx;
                // arg4 = imee_arg.r10;
                // arg5 = imee_arg.r8;
                // arg6 = imee_arg.r9;
                // ret_addr = imee_arg.rip;
                // save_eflags = imee_arg.r11;
                // rsp = imee_arg.rsp;
            }
        }
        else if (imee_arg.syscall_flag == 1)//this is return from syscall iuused from dota mode, as syscall_flag is set as 1 in the very first vcpu_entry
        {
            if (imee_arg.rax == 0xc || imee_arg.rax == 0x9 || imee_arg.rax == 30)//brk; mmap; shmat;
            {
                // if (arg == 0xffffffffffffffff)//return error in these syscall handling
                if (arg > user_end || arg < user_start)//return error in these syscall handling
                {
                    printk ("mmap/brk/shmat return pinter outside of user address range. \n");
                    imee_arg.ret_rax = arg;
                }
                else
                {
                    // DBG ("arg: %lx. \n", arg);
                    imee_arg.ret_rax = arg + UK_OFFSET;
                }
            }
            else//for brk, the return value is 0/-1, not true?
            {
                if (imee_arg.rax == 19 || imee_arg.rax == 20)//readv; writev; the adjusted memory should be adjusted back
                {
                    unsigned long iov_ptr_addr;
                    // unsigned long iov_addr;
                    iov_ptr_addr = imee_arg.rsi;
                    // iov_addr = *((unsigned long *) iov_ptr_addr);
                    *((unsigned long*)iov_ptr_addr) += UK_OFFSET;
                }

                else if (imee_arg.rax == 46 || imee_arg.rax == 47)//sendmsg; recvmsg;
                {
                    unsigned long* msghdr_addr;
                    unsigned long msg_name_addr;
                    unsigned long msg_iov_ptr_addr;
                    unsigned long msg_iov_addr;
                    unsigned long msg_control_addr;
                    msghdr_addr = imee_arg.rsi;
                    msg_name_addr = msghdr_addr;
                    msg_iov_ptr_addr = msghdr_addr + 0x2;
                    msg_iov_addr = *((unsigned long*) msg_iov_ptr_addr);
                    msg_control_addr = msghdr_addr + 0x4;
                    *((unsigned long*)msg_name_addr) += UK_OFFSET;
                    *((unsigned long*)msg_iov_ptr_addr) += UK_OFFSET;
                    *((unsigned long*)msg_control_addr) += UK_OFFSET;
                    *((unsigned long*)msg_iov_addr) += UK_OFFSET;
                }
                // printk ("return value for brk: %lx\n", arg);
                //
                //for debug
                else if (imee_arg.rax == 51)//getsockname
                {
                    unsigned long* temp_ptr;
                    temp_ptr = imee_arg.rsi;
                    printk ("temp_ptr: %p, content: %lx\n", temp_ptr, *temp_ptr);
                    temp_ptr ++;
                    printk ("temp_ptr: %p, content: %lx\n", temp_ptr, *temp_ptr);
                }

                imee_arg.ret_rax = arg;
            }
            printk ("return from syscall handling, ret value: %lx. \n", imee_arg.ret_rax);
            r = vcpu_reentry();
            // printk("when return from dota mode, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            // return;
            if (r == -2)
            {
                if (imee_arg.rax != 231)//set bp if not exit_group syscall
                {
                    dr_s = 0x401;
                    dr_z = imee_arg.rip;
                    set_bp(dr_z, dr_s); 
                }
                syscall_bounce ();
            }
            else 
            {
                printk ("onsite process should exit due to unexpected error, returned r: %d from vcpu_reentry \n", r);
                /* sth went wrong in oasis life cycle, free oasis related objects and issue exit syscall directly? */
                imee_arg.rax = 231;
                imee_arg.rdi = 0;
                syscall_bounce ();
                // arg2 = imee_arg.rsi;
                // arg3 = imee_arg.rdx;
                // arg4 = imee_arg.r10;
                // arg5 = imee_arg.r8;
                // arg6 = imee_arg.r9;
                // ret_addr = imee_arg.rip;
                // save_eflags = imee_arg.r11;
                // rsp = imee_arg.rsp;
            }
        }
    }
// out:
    return;
}

static void debug_handler (void);
asm (" .text");
asm (" .type    debug_handler, @function");
asm ("debug_handler: \n");
// asm ("cli \n");
asm ("swapgs \n");
asm ("pushq %rbx \n");
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushq %rcx \n");//save user space rip
asm ("pushq %r11 \n");//save user space eflags
asm ("pushq %rax \n");//save return value of syscall
asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("movq %rax, %rdi \n");//the arg of deter should be passed in register
asm ("callq enter_vcpu \n");
// // asm ("callq new_handler \n");
asm ("movq $0x400, %rax \n");
asm ("movq %rax, %DR7 \n");
asm ("movq $0x0, %rax \n");
asm ("movq %rax, %DR0 \n");
asm ("movq $0xfffe0ff0, %rax \n");
asm ("movq %rax, %DR6 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");
asm ("popq %r11 \n");
asm ("popq %rcx \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("swapgs \n");
// asm ("sti \n");
asm ("iretq \n");

unsigned long* idt;
unsigned long old_debug_desc;
void debug_mod (void)
{
    unsigned char idtr[10];
    gate_desc s;

    asm ("sidt %0":"=m"(idtr)::);

    idt = (unsigned long*)(*(unsigned long*)(idtr + 2));
    DBG ("idt: %lx\n", *idt);
    
    old_debug_desc = idt[3];
    DBG ("old_debug_desc: %lx\n", old_debug_desc);
    old_debug_desc = idt[2];
    DBG ("old_debug_desc: %lx\n", old_debug_desc);
    pack_gate (&s, GATE_INTERRUPT, (unsigned long) debug_handler, 0, 3, __KERNEL_CS);//0:dpl; 3:ist;
    printk ("new_debug_desc: %lx\n", *((unsigned long*)(&s)));
    idt[0x1*2] = *((unsigned long*) (&s));
    // //idt[0x1*2 + 1] = 0x00000000ffffffffUL;
    // unsigned long cr3;
    // asm volatile("movq %%cr3, %%rax; \n\t"
    //         "movq %%rax, %0; \n\t"
    //         :"=m"(cr3)::"%rax");
    // // printk ("----------------------cr3 in insmod breakpoint: %lx\n", cr3);
    return;
}

int init ( void)
{

    // WP bit may be getting into our way...
    clear_WP_bit ();

    elf_mod ();
    debug_mod ();

    set_WP_bit ();

    printk ("backup old code: ");
    print_bytes (old_bytes, 5);
    printk ("new loader code: ");
    print_bytes (old_loader_start, 5);

    // now crash..

    return 0;
}

void clean ( void )
{
    clear_WP_bit ();
    memcpy (old_loader_start, old_bytes, 5);
    DBG ("recover old_loader_code. \n");
    
    idt[2] = old_debug_desc;
    DBG ("recover debug_desc as: %lx\n", idt[2]);
    
    set_WP_bit ();
}

MODULE_LICENSE ("GPL");
module_init (init);
module_exit (clean);
