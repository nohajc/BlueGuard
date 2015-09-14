#ifndef _REGS_
#define _REGS_

#include <stdint.h>
#include "vmx_api.h"

#define EFLAGS_VM (1 << 17)
#define EFLAGS_IOPL3 (3 << 12)

#define CPUID_PSE (1 << 3)

typedef struct
{
  uint16_t limit_0_15;
  uint16_t base_0_15;
  uint8_t base_16_23;
  uint8_t attr_0_7;
  uint8_t limit_16_19_attr_8_11;
  uint8_t base_24_31;
} __attribute__ ((packed)) GDT_ENTRY;

typedef struct
{
  uint16_t offset_0_15;
  uint16_t segment_sel;
  uint8_t attr;
  uint8_t p_dpl_type;
  uint16_t offset_16_31;
  uint32_t offset_32_63;
  uint32_t reserved;
} __attribute__ ((packed)) IDT_ENTRY;

enum
{
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
  LDTR,
  TR
};

typedef struct{
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rbx;
  uint64_t rsp;
  uint64_t rbp;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  HVM * hvm;
} __attribute__ ((packed)) GUEST_REGS;

uint64_t get_rbp(void);
uint64_t get_rsp(void);
uint64_t get_cs(void);
uint64_t get_ds(void);
uint64_t get_es(void);
uint64_t get_fs(void);
uint64_t get_gs(void);
uint64_t get_ss(void);
uint64_t get_tr(void);
uint64_t get_cr0(void);
uint64_t get_cr3(void);
uint64_t get_cr4(void);
uint64_t get_dr7(void);
uint64_t get_rflags(void);
void get_gdt_base_limit(uint64_t * base, uint16_t * limit);
void get_idt_base_limit(uint64_t * base, uint16_t * limit);
uint64_t get_ldtr(void);
uint64_t get_msr(uint64_t index);
uint64_t set_msr(uint64_t index, uint64_t value);

void set_tr(uint64_t sel);
void set_gdt_base_limit(uint64_t base, uint64_t limit);

#endif