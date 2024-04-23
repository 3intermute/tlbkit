#include <linux/init.h>
#include <linux/linkage.h>


#include "include/tlbkit.h"
#define PT_REGS_SIZE        72


.text
.pushsection	.tlbkit.text, "ax"

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



SYM_FUNC_START(tlbkit_lockdown_itlb_addr)
    dsb
    mov         r1, r0
    mcr         p15, 0, r1, c8, c5, 1
    ldr         r0, =0x10000001 @ base should be 1, victim 0 ?
    ldr         r2, =0x01000000 @ base should be 1, victim 1, P = 0 !!
    mcr         p15, 0, r0, c10, c0, 1
    mcr         p15, 0, r1, c10, c1, 1
    mcr         p15, 0, r2, c10, c0, 1
    dsb
    isb
    mov         pc, lr
SYM_FUNC_END(tlbkit_lockdown_itlb_addr)



SYM_FUNC_START(tlbkit_flush_tlb_overkill)
    dsb
    mov     r0, 0
    MCR     p15, 0, r0, c7, c5, 0       @ Invalidate Instruction Cache

    MCR     p15, 0, r0, c7, c5, 6       @ Invalidate branch prediction array

    @ MCR     p15, 0, r0, c8, c7, 0       @ Invalidate entire Unified Main TLB
    MCR p15, 0, r0, c8, c5, 0 @ Invalidate Inst-TLB
    MCR p15, 0, r0, c8, c6, 0 @ Invalidate Data-TLB
    dsb
    isb                             @ instr sync barrier
    mov     pc, lr
SYM_FUNC_END(tlbkit_flush_tlb_overkill)



.align 12
.globl tlbkit_handler_dispatch
SYM_FUNC_START(tlbkit_handler_dispatch)
    @@@ TODO: ? alloc + copy context
    @@@       https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/entry-armv.S#L97
    @@@ call tlbkit_hook_handler_1
    push {lr}
    bl       tlbkit_hook_handler_1

    @@@ TODO: ? restore context, restore stack ?

@ copy orig overwritten here
@ pop orig r0
@ pop     {r0}

    pop {lr}

.globl tlbkit_handler_dispatch_reloc
tlbkit_handler_dispatch_reloc:
@ TODO: !! we can make this only a relative branch as it will copied to lowmem, !! define offsets constants
@    nop @ mov r0, 222,      overwritten by push r0
@    nop @ mov pc, lr,       overwritten by mov32 r0, =tlbkit_handler_dispatch
@    nop @                   ^
@    nop @                   overwritten by bx r0


    nop @ mov r0, 222,      overwritten by b  tlbkit_handler_dispatch, 32MB pc relative

@ branch orig
.globl tlbkit_handler_dispatch_reloc_a
tlbkit_handler_dispatch_reloc_a:
    @ TODO: !! copy this to lowmem so we can do this shit in 1 inst for kernel text,
    @          - this is fine for now bc tlbkit_bad is within highmem
    nop      @ mov pc, pc -tlbkit_handler_dispatch_reloc_a + addr + TLBKIT_HOOK_WIDTH
.align 12
SYM_FUNC_END(tlbkit_handler_dispatch)









@ @ deprecated
@ SYM_FUNC_START(tlbkit_invl_dtlb_addr)
@     mov         r1, r0
@     mcr         p15, 0, r1, c8, c6, 1
@     mov         pc, lr
@ SYM_FUNC_END(tlbkit_invl_dtlb_addr)
@
@ SYM_FUNC_START(tlbkit_invl_itlb_addr)
@     mov         r1, r0
@     mcr         p15, 0, r1, c8, c5, 1
@     mov         pc, lr
@ SYM_FUNC_END(tlbkit_invl_itlb_addr)
@
@ SYM_FUNC_START(tlbkit_flush_preload_dtlb)
@     mov         r1, r0
@     mcr         p15, 0, r1, c8, c6, 1
@     @ WRONG read manual
@     @ mcr         p15, 0, r1, c10, c1, 0
@     mov         pc, lr
@ SYM_FUNC_END(tlbkit_flush_preload_dtlb)
@
@ SYM_FUNC_START(tlbkit_flush_preload_itlb)
@     mov         r1, r0
@     mcr         p15, 0, r1, c8, c5, 1
@     @ mcr         p15, 0, r1, c10, c1, 1
@     mov         pc, lr
@ SYM_FUNC_END(tlbkit_flush_preload_itlb)

.popsection
