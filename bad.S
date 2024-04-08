#include <linux/init.h>
#include <linux/linkage.h>


#include "include/tlbkit.h"

.text
.pushsection	.kvmrk.text, "ax"

.align 12
SYM_FUNC_START(tlbkit_bad)
    mov         r0, 222
    mov         pc, lr
SYM_FUNC_END(tlbkit_bad)

.align 12
SYM_FUNC_START(tlbkit_lockdown_itlb_addr)
    mov         r1, r0
    mcr         p15, 0, r1, c8, c5, 1
    ldr         r0, =0x00000001
    ldr         r2, =0x08400000
    mcr         p15, 0, r0, c10, c0, 1
    mcr         p15, 0, r1, c10, c1, 1
    mcr         p15, 0, r2, c10, c0, 1
    mov         pc, lr
SYM_FUNC_END(tlbkit_lockdown_itlb_addr)

SYM_FUNC_START(tlbkit_invl_dtlb_addr)
    mov         r1, r0
    mcr         p15, 0, r1, c8, c5, 0
    mov         pc, lr
SYM_FUNC_END(tlbkit_invl_dtlb_addr)

SYM_FUNC_START(tlbkit_invl_itlb_addr)
    mov         r1, r0
    mcr         p15, 0, r1, c8, c5, 1
    mov         pc, lr
SYM_FUNC_END(tlbkit_invl_itlb_addr)

.popsection
