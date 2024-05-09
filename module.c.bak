#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/vmalloc.h>      // vmalloc
#include <linux/slab.h>         // kmalloc
#include <linux/smp.h>          // smp_processor_id
#include <linux/mm.h>           // is_vmalloc_or_module_addr
// #include <linux/pgtable.h>   // set_pte_at NOT EXPORTED
// #include <asm/pgtable.h>     // i forgor ??

#include <asm/proc-fns.h>       // set_pte_ext
#include <asm/ptrace.h>         // struct pt_regs


#include <asm/cacheflush.h>     // flush_cache_all
// #include <asm/tlbflush.h>    // flush_tlb_all NOT EXPORTED



#include "include/assembler.h"
#include "include/resolve_kallsyms.h"
#include "include/set_page_flags.h"
#include "include/helpers.h"
#include "linux/gfp.h"
#include "linux/preempt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("tlbkit");
MODULE_VERSION("0.1");




extern int tlbkit_bad(uint32_t r0);


extern uint32_t tlbkit_read_itlb_lockdown(void);
extern uint32_t tlbkit_get_asid(void);
extern uint32_t tlbkit_read_c1(void);

extern void tlbkit_prefetch_itlb(uint32_t addr);
extern void tlbkit_lockdown_itlb_addr(uint32_t addr);



extern void handler_entry(void);
extern void __reloc0_handler_entry(void);
// extern void __reloc1_handler_entry(void);

extern uint32_t __ret_addr_handler_entry;


// void (*tlbkit_set_pte_at)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;
void (*internal_flush_tlb_all)(void) = NULL;
int (*internal_is_vmalloc_or_module_addr)(const void *) = NULL;

// update if shellcode changed
// #define TLBKIT_HOOK_LENGTH         (ARM_INST_WIDTH)
#define TLBKIT_HOOK_LENGTH         (ARM_INST_WIDTH * 4)

// // TODO: allow registering multiple handlers
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


void tlbkit_hook_handler(struct pt_regs *regs) {
// void tlbkit_hook_handler_1(void) {
    printk(KERN_INFO "tlbkit: HOOK HANDLER\n");
    printk(KERN_INFO "          regs->r0: %lx\n", regs->uregs[0]);
    printk(KERN_INFO "          regs->lr: %lx\n", regs->uregs[14]);
    regs->uregs[0] = 123;
    printk(KERN_INFO "          SET regs->r0 to %lx\n", regs->uregs[0]);

    return;
}

void tlbkit_place_hook(uint32_t addr) {
    printk(KERN_INFO "tlbkit_place_hook: func_%lx\n", addr);

    // check hooking non-page aligned funcs,
    uint32_t addr_aligned = addr & PAGE_MASK;


    // make reloc page writeable
    ptep_flip_write_protect(virt_to_ptep(handler_entry));
    flush_cache_all();
    internal_flush_tlb_all();

    // perform relocs
    memcpy(__reloc0_handler_entry, addr, TLBKIT_HOOK_LENGTH);
    __ret_addr_handler_entry = addr + TLBKIT_HOOK_LENGTH;

    ptep_flip_write_protect(virt_to_ptep(handler_entry));
    flush_cache_all();
    internal_flush_tlb_all();




    uint32_t __va_bad_pg = kmalloc(PAGE_SIZE, GFP_KERNEL); // GFP_KERNEL correct ?
    uint32_t __pa_bad_pg = virt_to_phys(__va_bad_pg);
    internal_memcpy(__va_bad_pg, addr_aligned, PAGE_SIZE); // !! slow copy full orig page

    // copy hook, FLUSH CACHE !!
    // hook:
    //      push        {r0}
    //      mov32       r0, handler_entry
    //      mov32       r0, handler_entry ...
    //      bx          r0
    uint32_t addr_bad = __va_bad_pg + (addr & ~PAGE_MASK);
    *((uint32_t *) addr_bad) = 0xe52d0004;                                                     // push         {r0}
    assemble_mov32(handler_entry, 0, (uint32_t *)(addr_bad + ARM_INST_WIDTH));                 // mov32        r0, handler_entry
    *((uint32_t *)(addr_bad + ARM_INST_WIDTH + ARM_MOV32_LENGTH)) = 0xe12fff10;                // bx           r0
    flush_cache_all();

    pte_t *__ptep_orig_pg = virt_to_ptep(addr);
    pte_t __pte_orig_pg = *__ptep_orig_pg;
    uint32_t __pa_orig_pg;
    if (internal_is_vmalloc_or_module_addr(addr)) {
        __pa_orig_pg = highmem_virt_to_phys(addr);
    }
    else {
        __pa_orig_pg = virt_to_phys(addr);
    }

    printk(KERN_INFO "      tlbkit_get_asid: %lx\n", tlbkit_get_asid());
    printk(KERN_INFO "      orig_page: va @%lx, pa @%lx\n", addr_aligned, __pa_orig_pg);
    printk(KERN_INFO "      bad_page: va @%lx, pa @%lx\n", __va_bad_pg, __pa_bad_pg);

    preempt_disable();
    // replace phys
    set_pte_ext(__ptep_orig_pg, pte_mkwrite(pfn_pte(__pa_bad_pg >> PAGE_SHIFT, PAGE_KERNEL_EXEC)),  0);
    flush_cache_all();
    internal_flush_tlb_all();

    // DONE, behavior correct: TEST WITHOUT LOCKDOWN + prefetch
    // prefetch new phys to itlb
    printk(KERN_INFO "PRE LOCKDOWN ->  tlbkit_read_itlb_lockdown: %lx, smp_processor_id: %d\n", tlbkit_read_itlb_lockdown(), smp_processor_id());
    tlbkit_lockdown_itlb_addr(addr); // TODO: for SMP systems do on all cores
    // tlbkit_prefetch_itlb(addr);
    printk(KERN_INFO "POST LOCKDOWN -> tlbkit_read_itlb_lockdown: %lx, smp_processor_id: %d\n", tlbkit_read_itlb_lockdown(), smp_processor_id());

    printk(KERN_INFO "[CORRECT?]        addr_bad: %lx, *addr_bad: %lx\n", addr_bad, *((uint32_t *) addr_bad));
    printk(KERN_INFO "[CORRECT?]        addr: %lx, *addr: %lx\n", addr, *((uint32_t *) addr));

    // restore orig phys
    set_pte_ext(__ptep_orig_pg, __pte_orig_pg, 0);
    flush_cache_all();
    internal_flush_tlb_all();

    preempt_enable();
}


static int __init tlbkit_init(void)
{
    printk(KERN_INFO "tlbkit: module loaded, PAGE_SIZE %lx\n", PAGE_SIZE);
    printk(KERN_INFO "tlbkit: tlbkit_read_c1: %lx", tlbkit_read_c1());

    init_init_mm_ptr();
    internal_flush_tlb_all = rk_kallsyms_lookup_name("flush_tlb_all");
    internal_is_vmalloc_or_module_addr = rk_kallsyms_lookup_name("is_vmalloc_or_module_addr");

    printk(KERN_INFO "tlbkit: PRE-HOOK\n");
    printk(KERN_INFO "          `func_%lx()` returns %d\n", tlbkit_bad, tlbkit_bad(333));
    printk(KERN_INFO "          `func_%lx` read returns %lx\n", tlbkit_bad, *((uint32_t *) tlbkit_bad));


    tlbkit_place_hook(tlbkit_bad + ARM_INST_WIDTH);
    printk(KERN_INFO "tlbkit: POST-HOOK\n");
    printk(KERN_INFO "          `func_%lx()` returns %d\n", tlbkit_bad, tlbkit_bad(333));
    printk(KERN_INFO "          `func_%lx` read returns %lx\n", tlbkit_bad, *((uint32_t *) tlbkit_bad));

    printk(KERN_INFO "tlbkit: flushing cache + tlb again, ? is prefetch buffer flushed ?\n");
    flush_cache_all();
    internal_flush_tlb_all();
    printk(KERN_INFO "          `func_%lx()` returns %d\n", tlbkit_bad, tlbkit_bad(333));
    printk(KERN_INFO "          `func_%lx` read returns %lx\n", tlbkit_bad, *((uint32_t *) tlbkit_bad));

    return 0;
}

static void __exit tlbkit_exit(void)
{
    printk(KERN_INFO "tlbkit: module unloaded\n");
}

module_init(tlbkit_init);
module_exit(tlbkit_exit);
