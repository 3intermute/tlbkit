#ifndef _ASSEMBLER_H_
#define _ASSEMBLER_H_

#include <linux/types.h>
#include <linux/delay.h>

#define ARM_INST_WIDTH             4
#define ARM_MOV32_N_INST           2

// arm32
uint32_t assemble_movw(uint32_t imm16, uint32_t rd) {
    imm16 = imm16 & 0xffff;
    rd = rd & 0xf;
    return cpu_to_le32(0xe3000000 | ((imm16 & 0xf000) << 4) | (rd << 12) | (imm16 & 0xfff));
}

uint32_t assemble_movt(uint32_t imm16, uint32_t rd) {
    imm16 = imm16 & 0xffff;
    rd = rd & 0xf;
    return cpu_to_le32(0xe3400000 | ((imm16 & 0xf000) << 4) | (rd << 12) | (imm16 & 0xfff));
}

// arr size should be 2 * sizeof(uint32_t)
void assemble_mov32(uint32_t addr, uint32_t rd, uint32_t *dest) {
    dest[0] = assemble_movw(addr, rd);
    dest[1] = assemble_movt(((addr >> 16)), rd);
}

uint32_t assemble_b(uint32_t imm24) {
    // shfit by 2:
    //      https://stackoverflow.com/questions/53944210/how-does-an-the-arm-branch-instruction-address-work
    // https://iitd-plos.github.io/col718/ref/arm-instructionset.pdf page 8:
    //      The branch offset must take account of the prefetch operation, which causes the PC to be 2 words (8 bytes) ahead of the current instruction.
    uint32_t _imm24 = imm24;
    imm24 = ((imm24 - 8) >> 2) & 0xffffff;
    printk(KERN_INFO "debug: imm24 %ld, mov pc, pc + imm24 -> %lx\n", _imm24, (0xea000000 | imm24));
    return 0xea000000 | imm24;
}



// arm64
/*
// https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/MOVK--Move-wide-with-keep-?lang=en
// movk encoding:
// 0 | 1 1 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
// ------------------------------------------------------------------------
// sf|opc              |hw   |imm16                            |rd
uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd) {
    return 0xf2800000 | (imm16 << 5) | (hw << 21) | rd;
}

void assemble_absolute_load(uint32_t rd, uintptr_t addr, uint32_t *arr) {
    arr[0] = cpu_to_le32(assemble_movk(addr & 0xffff, 0b0, rd));
    arr[1] = cpu_to_le32(assemble_movk((addr & 0xffff0000) >> 16, 0b1, rd));
    arr[2] = cpu_to_le32(assemble_movk((addr & 0xffff00000000) >> 32, 0b10, rd));
    arr[3] = cpu_to_le32(assemble_movk((addr & 0xffff000000000000) >> 48, 0b11, rd));
}
*/



#endif
