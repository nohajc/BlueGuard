#ifndef _VMX_EMU_
#define _VMX_EMU_

#include <stdint.h>

void emu_rdmsr(uint64_t rcx, uint64_t * rdx, uint64_t * rax);
void emu_wrmsr(uint64_t rcx, uint64_t rdx, uint64_t rax);
void emu_mov_reg_cr3(uint64_t * reg, uint64_t cr3);
void emu_cpuid(uint64_t * rax, uint64_t * rbx, uint64_t * rcx, uint64_t * rdx);

#endif