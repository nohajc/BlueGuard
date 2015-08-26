#ifndef _AP_TRAMPOLINE_
#define _AP_TRAMPOLINE_

#include <stdint.h>
#include "smp.h"

void init_tramp(void);
extern uint32_t tramp_size;

extern struct{
	uint16_t addr;
	uint16_t seg;
} __attribute__((packed)) JMP_START_PTR;

extern struct{
	uint32_t addr;
	uint16_t seg;
} __attribute__((packed)) JMP_32_PTR;

extern struct{
	uint32_t addr;
	uint16_t seg;
} __attribute__((packed)) JMP_64_PTR;

extern uint64_t AP_32_LABEL;

extern uint64_t AP_64_LABEL;

extern uint64_t AP_START_LABEL;

extern struct{
	uint16_t limit;
	uint64_t base;
} __attribute__((packed)) GDTR32;

extern uint64_t GDT32_LABEL;

extern struct{
	uint16_t limit;
	uint64_t base;
} __attribute__((packed)) AP_GDTR;

extern struct{
	uint16_t limit;
	uint64_t base;
} __attribute__((packed)) AP_IDTR;

extern uint32_t AP_CR3;

extern uint32_t ACTIVE_CPU_CNT;

//extern uint64_t AP_STACK;

void ap_tramp32(void);
void ap_tramp64(void);

#endif