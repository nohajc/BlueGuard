#ifndef _VMCS_
#define _VMCS_

#include "vmx_api.h"

typedef struct{
	bool pse;
} FEATURES;

extern FEATURES features;

void vmcs_init(HVM * hvm);
void vm_start(void);
uint32_t init_control_field(uint32_t ctl, uint32_t msr);
void set_guest_selector(uint64_t gdt_base, uint32_t reg, uint64_t sel);

#endif