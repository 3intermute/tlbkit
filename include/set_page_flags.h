#ifndef _SET_PAGE_FLAGS_H_
#define _SET_PAGE_FLAGS_H_


#include <linux/pgtable.h>
// #include <asm/pgtable.h>
// #include <linux/align.h>
#include "resolve_kallsyms.h"

// holy shit arm32 is weird
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm/include/asm/pgtable-2level.h

struct mm_struct *init_mm_ptr = NULL;
struct mm_struct *(*internal_copy_init_mm)(void) = NULL;

static void init_init_mm_ptr(void) {
    if (!init_mm_ptr) {
        internal_copy_init_mm = rk_kallsyms_lookup_name("copy_init_mm");
        init_mm_ptr = internal_copy_init_mm();
        printk(KERN_INFO "debug: init_mm_ptr->pgd: %lx\n", init_mm_ptr->pgd);
        printk(KERN_INFO "                   *pgd: %lx\n", *(init_mm_ptr->pgd));
    }
}

// // #define internal_pgd_offset_k(address)		pgd_offset(init_mm_ptr, (address))
// pgd_offset_pgd(pgd, (address))

// static inline pmd_t *internal_pmd_off_k(unsigned long va)
// {
//     init_init_mm_ptr();
// 	return pmd_offset(pud_offset(p4d_offset(internal_pgd_offset_k(va), va), va), va);
// }

// static inline pte_t *internal_virt_to_kpte(unsigned long vaddr)
// {
// 	pmd_t *pmd = internal_pmd_off_k(vaddr);

// 	return pmd_none(*pmd) ? NULL : pte_offset_kernel(pmd, vaddr);
// }



// IMPORTANT: this only works for highmem addresses perhaps due to split ttbr0, ttbr1
pte_t *highmem_virt_to_ptep(uint32_t addr) {
    init_init_mm_ptr();

    addr &= PAGE_MASK; // TODO: do in 1 inst via PAGE_MASK

    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;

    pgdp = pgd_offset(init_mm_ptr, addr);
    // pgdp = pgd_offset_k(addr)
    if (pgd_none(*pgdp)) {
        return NULL;
    }

    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(*p4dp)) {
        return NULL;
    }

    pudp = pud_offset(p4dp, addr);
    if (pud_none(*pudp)) {
        return NULL;
    }

    // // not needed on arm32
    // if (pud_sect(*pudp)) {
    //     printk(KERN_INFO "debug: entry at pud virt_to_ptep success, virt (%pK), ptep @ %pK", addr, pudp);
    //     return pudp;
    // }

    pmdp = pmd_offset(pudp, addr);
    if (pmd_none(*pmdp)) {
        return NULL;
    }

    // // not needed on arm32
    // if (pmd_sect(*pmdp)) {
    //     printk(KERN_INFO "debug: entry at pmd virt_to_ptep success, virt (%pK), ptep @ %pK", addr, pmdp);
    //     return pmdp;
    // }


    ptep = pte_offset_kernel(pmdp, addr);
    if (!ptep) {
        return NULL;
    }

    printk(KERN_INFO "debug: virt_to_ptep success, virt (%lx), *ptep %lx\n", addr, *ptep);
    printk(KERN_INFO "debug:            pgd: %lx\n", pgdp);
    printk(KERN_INFO "                  *pgd: %lx\n", *(pgdp));
    // printk(KERN_INFO "debug:        ptep: %lx\n", ptep);
    // printk(KERN_INFO "debug:        pgdp: %lx\n", pgdp);
    // printk(KERN_INFO "debug:        *pgdp: %lx\n", *pgdp);
    // printk(KERN_INFO "----\n");

    return ptep;
}

pte_t *virt_to_ptep(uint32_t addr) {
    init_init_mm_ptr();

    // return internal_virt_to_kpte(addr);
    return highmem_virt_to_ptep(addr);
}


void ptep_flip_write_protect(pte_t *ptep) {
    if (!pte_write(*ptep)) {
            printk(KERN_INFO "ptep_flip_write_protect: ptep %lx not writeable, flipping, *ptep %lx\n", ptep, *ptep);
            set_pte_ext(ptep, pte_mkwrite(*ptep), 0);
            printk(KERN_INFO "                         ptep %lx, *ptep %lx, pte_write(*ptep) %d\n", ptep, *ptep, pte_write(*ptep));
    }
    else {
        printk(KERN_INFO "ptep_flip_write_protect: ptep %lx writeable, flipping\n", ptep);
        set_pte_ext(ptep, pte_wrprotect(*ptep), 0);
    }
}

static unsigned long highmem_pte_to_phys(pte_t *ptep) {
    struct page *p = pte_page(*ptep);
    return page_to_phys(p);
}

static unsigned long highmem_virt_to_phys(unsigned long addr) {
    unsigned long off = addr & ~PAGE_MASK;
    unsigned long r = highmem_pte_to_phys(virt_to_ptep(addr)) + off;
    // printk(KERN_INFO "debug: highmem_virt_to_phys on addr %lx, off %lx -> %lx\n", addr, off, r);
    return r;
}


#endif
