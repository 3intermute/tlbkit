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



@ FIX THIS !!, actually survies flush_tlb_all so maybe its correct ?
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



@ COPY ME !!
.align 12
.globl tlbkit_handler_dispatch
SYM_FUNC_START(tlbkit_handler_dispatch)
    @@@ TODO: ? alloc + copy context
    @@@       https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/entry-armv.S#L97
    sub         sp, sp, #PT_REGS_SIZE
    stmia	    sp,     {r0 - lr}

    @@@ call tlbkit_hook_handler_1
    @ push {lr}
    mov      r0, sp
    bl       tlbkit_hook_handler_1

    @@@ TODO: ? restore context, restore stack ?
    @ pop {lr}
    ldmia       sp, {r0 - lr}
    add         sp, sp, #PT_REGS_SIZE
    .globl tlbkit_handler_dispatch_reloc
tlbkit_handler_dispatch_reloc:
@ TODO: !! we can make this only a relative branch as it will copied to lowmem, !! define offsets constants
    nop @ mov r0, 222,      overwritten by b  tlbkit_handler_dispatch, 32MB pc relative

@ branch orig
.globl tlbkit_handler_dispatch_reloc_a
tlbkit_handler_dispatch_reloc_a:
    @ TODO: !! copy this to lowmem so we can do this shit in 1 inst for kernel text,
    @          - this is fine for now bc tlbkit_bad is within highmem
    nop      @ b -tlbkit_handler_dispatch_reloc_a + addr + ARM_INST_WIDTH
SYM_FUNC_END(tlbkit_handler_dispatch)
.align 12


.popsection
