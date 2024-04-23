#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h> // kmalloc
#include <linux/smp.h> // smp_processor_id
#include <linux/pgtable.h> // set_pte_at, NOT EXPORTED
#include <asm/pgtable.h> // ? i forgor

#include <asm/proc-fns.h> // set_pte_ext
#include <asm/ptrace.h> // pt_regs

// #include <asm/tlbflush.h> // flush_tlb_all
#include <asm/cacheflush.h> // flush_cache_mm


#include "include/assembler.h"
#include "include/set_page_flags.h"
#include "include/helpers.h"
#include "linux/preempt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("tlbkit");
MODULE_VERSION("0.1");




extern int tlbkit_bad(void);

extern void tlbkit_lockdown_itlb_addr(uint32_t addr);
extern void tlbkit_flush_tlb_overkill(void);


extern uint32_t tlbkit_read_itlb_lockdown(void);
extern uint32_t tlbkit_get_asid(void);
extern uint32_t tlbkit_read_c1(void);

extern void tlbkit_handler_dispatch(void);
extern void tlbkit_handler_dispatch_reloc(void);
extern void tlbkit_handler_dispatch_reloc_a(void);


void (*tlbkit_set_pte_at)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;
void (*tlbkit_flush_tlb_all)(void) = NULL;


// update if shellcode changed
// #define TLBKIT_HOOK_WIDTH    ARM_MOV32_WIDTH
// #define TLBKIT_HOOK_WIDTH         ((ARM_INST_WIDTH * ARM_MOV32_INSTS) + (ARM_INST_WIDTH * 2))
#define TLBKIT_HOOK_WIDTH         (ARM_INST_WIDTH)

// // register multiple handlers
// typedef void (*tlbkit_hook_handler_t)(struct pt_regs *regs);


void internal_memcpy(void *dest, void *src, size_t n) {
   int i;
   uint8_t *src_char = (uint8_t *) src;
   uint8_t *dest_char = (uint8_t *) dest;
   for (i = 0; i < n; i++) {
       dest_char[i] = src_char[i];
   }
}


// void tlbkit_hook_handler_1(struct pt_regs *regs) {
void tlbkit_hook_handler_1(void) {
    printk(KERN_INFO "tlbkit: LETS FUCKING GOOOOO\n");
    return;
}

void tlbkit_place_hook(uint32_t addr) {
    printk(KERN_INFO "tlbkit_place_hook: addr: %lx\n", addr);
    printk(KERN_INFO "tlbkit_place_hook: tlbkit_handler_dispatch: %lx\n", tlbkit_handler_dispatch);
    // make reloc page writeable
    ptep_flip_write_protect(virt_to_ptep(tlbkit_handler_dispatch));
    ptep_flip_write_protect(virt_to_ptep(addr));
    flush_cache_all();
    tlbkit_flush_tlb_all();
    internal_memcpy(tlbkit_handler_dispatch_reloc, addr, TLBKIT_HOOK_WIDTH);

    uint32_t __reloc_a__to_copy = assemble_b((0 - (int32_t) tlbkit_handler_dispatch_reloc_a) + addr + TLBKIT_HOOK_WIDTH); // sign extend imm24 00 -> imm32
    internal_memcpy(tlbkit_handler_dispatch_reloc_a, &__reloc_a__to_copy, ARM_INST_WIDTH);

    preempt_disable();
    // correct: b #0xffffdff4, EAFFF7FB
    // current: b #0x00ffdff4, ea3ff7fb
    uint32_t __hook__to_copy = assemble_b((0 - (uint32_t) tlbkit_bad) + (uint32_t) tlbkit_handler_dispatch);
    internal_memcpy(addr, &__hook__to_copy, TLBKIT_HOOK_WIDTH);
    flush_cache_all();
    tlbkit_flush_tlb_all();
    preempt_enable();



    // // copy overwritten insts
    // internal_memcpy(&tlbkit_handler_dispatch_reloc, (void *) addr, TLBKIT_HOOK_WIDTH);

    // // mov32      pc, addr + TLBKIT_HOOK_LEN * ARM64_INST_WIDTH
    // uint32_t h__reloc_a[ARM_INST_WIDTH * ARM_MOV32_INSTS];
    // assemble_mov32(addr + (TLBKIT_HOOK_WIDTH), 15, h__reloc_a);
    // memcpy(&tlbkit_handler_dispatch_reloc_a, h__reloc_a, ARM_MOV32_INSTS * ARM_INST_WIDTH);
    //
    // // place hook
    // uint32_t h__hook[TLBKIT_HOOK_WIDTH];
    // // 1.     push {r0}
    // unsigned char h__push_r0[] = {
    //     0x04, 0x00, 0x2d, 0xe5,
    // };
    // internal_memcpy(&(h__hook[0]), h__push_r0, ARM_INST_WIDTH);
    //
    // // 2.     mov32     r0, =tlbkit_handler_dispatch
    // assemble_mov32(&tlbkit_handler_dispatch, 0, &(h__hook[1]));

    // // 3.     bx        r0
    // unsigned char h__bx_r0[] = {
    //     0x10, 0xff, 0x2f, 0xe1,
    // };
    // internal_memcpy(&(h__hook[3]), h__bx_r0, ARM_INST_WIDTH);
    //
    // preempt_disable();
    // internal_memcpy((void *) addr, h__hook, TLBKIT_HOOK_WIDTH);

    // flush_cache_all();
    // tlbkit_flush_tlb_all();
    // preempt_enable();
}


static int __init tlbkit_init(void)
{
    printk(KERN_INFO "tlbkit: module loaded, PAGE_SIZE %lx\n", PAGE_SIZE);
    // printk(KERN_INFO "tlbkit: tlbkit_read_c1: %lx", tlbkit_read_c1());

    init_init_mm_ptr();
    tlbkit_set_pte_at = rk_kallsyms_lookup_name("set_pte_at");
    tlbkit_flush_tlb_all = rk_kallsyms_lookup_name("flush_tlb_all");

    // TODO: COPY PAGE FIRST TO NOT TAMPER WITH ORIGINAL PAGE
    tlbkit_place_hook(tlbkit_bad);
    printk(KERN_INFO "tlbkit: POST-HOOK testing !!\n");
    printk(KERN_INFO "          `tlbkit_bad()` returns %d\n", tlbkit_bad());
    printk(KERN_INFO "          `tlbkit_bad()` read returns %lx\n", *((uint32_t *) tlbkit_bad));



/*
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

    // align maybe ? MVA needs to be page aligned
*/
    return 0;
}

static void __exit tlbkit_exit(void)
{
    printk(KERN_INFO "tlbkit: module unloaded\n");
}

module_init(tlbkit_init);
module_exit(tlbkit_exit);
