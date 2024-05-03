#include <linux/init.h>
#include <linux/linkage.h>

#define PT_REGS_SIZE        72


.globl __ret_addr_handler_entry

.globl handler_entry
.globl __reloc0_handler_entry



.text
@ .pushsection	.tlbkit.text, "ax"

.align 12
SYM_FUNC_START(tlbkit_bad)
    mov         r0, 222
    mov         pc, lr
    nop
    nop
SYM_FUNC_END(tlbkit_bad)
.align 12



SYM_FUNC_START(tlbkit_read_itlb_lockdown)
    mrc         p15, 0, r0, c10, c0, 1
    mov         pc, lr
SYM_FUNC_END(tlbkit_read_itlb_lockdown)

SYM_FUNC_START(tlbkit_get_asid)
    mrc         p15, 0, r0, c13, c0, 1
    mov         pc, lr
SYM_FUNC_END(tlbkit_get_asid)

SYM_FUNC_START(tlbkit_read_c1)
    mrc         p15, 0, r0, c1, c1, 2
    mov         pc, lr
SYM_FUNC_END(tlbkit_read_c1)


SYM_FUNC_START(tlbkit_prefetch_itlb)
    mcr         p15, 0, r0, c8, c5, 1  @ Invalidate TLB entry corresponding to VA
    mcr         p15, 0, r0, c10, c1, 1 @ Prefetch I-TLB, note: prefetch needs to be -2 words ahead ?
    dsb
    isb
    mov         pc, lr
SYM_FUNC_END(tlbkit_prefetch_itlb)

@ FIX THIS !!, actually survies flush_tlb_all so maybe its correct ?
SYM_FUNC_START(tlbkit_lockdown_itlb_addr)
    dsb
    mov         r1, r0 @ Address of entry to lock
    mcr         p15, 0, r1, c8, c5, 1 @ Invalidate TLB entry corresponding to VA

    @ WRONG !! victim >= base + base must be next unlocked entry, !! increment !!
    ldr         r0, =0x00000001 @ base=victim=0 (protect bit=1 [lock])
    ldr         r2, =0x08400000 @ base=victim=1 (protect bit=0 [unlock])

    @ WRONG !! victim >= base + base must be next unlocked entry
    @ ldr         r0, =0x10000001 @ base should be 1, victim 0 ?
    @ ldr         r2, =0x01000000 @ base should be 1, victim 1, P = 0 !!

    mcr         p15, 0, r0, c10, c0, 1 @ Write I-TLB Lockdown Register
    mcr         p15, 0, r1, c10, c1, 1 @ Prefetch I-TLB, note: prefetch needs to be -2 words ahead ?
    mcr         p15, 0, r2, c10, c0, 1 @ Write I-TLB Lockdown Register
    dsb
    isb
    mov         pc, lr
SYM_FUNC_END(tlbkit_lockdown_itlb_addr)



@ COPY ME !!
.align 12
SYM_FUNC_START(handler_entry)
    pop             {r0}

    @ save context to struct pt_regs on stack, see: https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/entry-armv.S#L97
    sub             sp, sp, #PT_REGS_SIZE
    stmia	        sp, {r0 - lr}

    @ branch tlbkit_hook_handler
    mov             r0, sp
    bl              tlbkit_hook_handler

    @ restore context, restore stack
    ldmia           sp, {r0 - lr}
    add             sp, sp, #PT_REGS_SIZE

__reloc0_handler_entry:
@ TODO: !! define offsets constants
@ copy overwritten here
    nop
    nop
    nop
    nop

@ branch orig
    ldr             pc, __ret_addr_handler_entry
__ret_addr_handler_entry:
    .word 0
SYM_FUNC_END(handler_entry)
.align 12

@ .popsection
