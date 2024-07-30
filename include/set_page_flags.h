/****************************************************************************
 * Copyright (C) 2024 by wintermute                                         *
 *                                                                          *
 * This file is part of tlbkit.                                             *
 *                                                                          *
 *   tlbkit is free software: you can redistribute it and/or modify it      *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   tlbkit is distributed in the hope that it will be useful,              *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with tlbkit.  If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file arm32_vm_helpers.h
 * @author wintermute
 * @date 6/26/24
 * @brief provides helpers for managing virtual memory for arm32
 */

#ifndef _SET_PAGE_FLAGS_H_
#define _SET_PAGE_FLAGS_H_

#include <linux/pgtable.h>
#include <asm/proc-fns.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/highmem.h>

#include "resolve_kallsyms.h"


#define ALIGN_TO_4KB(addr) ((addr) & PAGE_MASK)
#define ALIGN_TO_1MB(addr) ((addr) & SECTION_MASK)


static struct mm_struct *init_mm_exported = NULL;
struct mm_struct *(*copy_init_mm_exported)(void) = NULL;
void (*set_pte_at_exported)(struct mm_struct *, unsigned long, pte_t *, pte_t) = NULL;

/**
 * @brief initializes internal copy of init_mm_ptr
 */
static void export_init_mm(void) {
    if (!init_mm_exported) {
        copy_init_mm_exported = kallsyms_lookup_name_exported("copy_init_mm");
        init_mm_exported = copy_init_mm_exported();
        printk(KERN_INFO "debug: init_mm_ptr->pgd: %lx\n", init_mm_exported->pgd);
        printk(KERN_INFO "                   *pgd: %lx\n", *(init_mm_exported->pgd));
    }
}

static void export_set_pte_at(void) {
    if (!set_pte_at_exported) {
        set_pte_at_exported = kallsyms_lookup_name_exported("set_pte_at");
    }
}

/**
 * @brief check if pgd corresponds to a 1mb section
 *
 * @param pgd pgd to check
 * @return -1 if pgd invalid, 0 if pgd is NOT sect, 1 if pgd is sect
 */
int is_pgd_1mb_sect(pgd_t pgd) {
    // implement
}

int is_addr_1mb_sect(unsigned long vaddr) {
    export_init_mm();
    pgd_t *pgd;

    pgd = pgd_offset(init_mm_exported, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        printk(KERN_INFO "debug: could not get pte of vaddr @%lx, bad pgd\n", vaddr);
        return -1;
    }
    if (is_pgd_1mb_sect(*pgd)) {
        printk(KERN_INFO "debug: vaddr @%lx is mapped as 1mb section\n", vaddr);
        return 1;
    }
    else {
        printk(KERN_INFO "debug: vaddr @%lx is mapped as 4kb page\n", vaddr);
        return 0;
    }
}

/**
 * @brief get pointer to pte of virtual address
 *
 * @param vaddr virtual address to get pte of
 * @return pointer to pte of vaddr
 */
pte_t *get_pte(unsigned long vaddr) {
    export_init_mm();

    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(init_mm_exported, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        printk(KERN_INFO "debug: could not get pte of vaddr @%lx, bad pgd\n", vaddr);
        return NULL;
    }
    if (is_pgd_1mb_sect(*pgd)) {
        printk(KERN_INFO "debug: vaddr @%lx is mapped as 1mb section\n", vaddr);
        // /TODO cannot cast directly to pte_t
        return (pte_t *) pgd;  // IMPORTANT: treat pgd as pte for 1mb sections
    }

    pmd = pmd_offset(pgd, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        printk(KERN_INFO "debug: could not get pte of vaddr @%lx, bad pmd\n", vaddr);
        return NULL;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    if (!pte) {
        printk(KERN_INFO "debug: could not get pte of vaddr @%lx, bad pte\n", vaddr);
        return NULL;
    }

    return pte;
}

/**
 * @brief set contents of pte
 *
 * \TODO refactor to use set_pte_ext, vaddr no longer needed
 *
 * @param[in] vaddr virtual address to set pte of
 * @param[out] dest pointer to destination pte
 * @param[in] src source pte
 */
void set_pte_wrapper(unsigned long vaddr, pte_t *dest, pte_t src) {
    export_init_mm();
    export_set_pte_at();

    // set_pte_at_exported(init_mm_exported, vaddr, dest, src);
    set_pte_ext(dest, src, 0);
}

/**
 * @brief remap virtual memory translation for virtual address
 *
 * ONLY FOR 1MB SECTIONS !!
 *
 * @param vaddr virtual address to set remap
 * @param paddr new physical address to translate to
 * @return orig pte
 */
pte_t remap_phys_1mb(unsigned long vaddr, unsigned long paddr) {
    pte_t *ptep_orig = get_pte(vaddr);
    pte_t pte_orig = *ptep_orig;
    set_pte_wrapper(vaddr, ptep_orig, pfn_pte(paddr >> SECTION_SHIFT, PAGE_KERNEL_EXEC));

    return pte_orig;
}

void flip_write_protect(unsigned long addr) {
    pte_t *ptep = get_pte(addr);
    if (!pte_write(*ptep)) {
        printk(KERN_INFO "debug: @%lx not writeable, flipping write bit\n", addr);
        set_pte_ext(ptep, pte_mkwrite(*ptep), 0);
    }
    else {
        printk(KERN_INFO "debug: @%lx writeable, flipping write bit\n", addr);
        set_pte_ext(ptep, pte_wrprotect(*ptep), 0);
    }
}

#endif
