#ifndef _VMCS_
#define _VMCS_

#include "vmx_api.h"

void vmcs_init(HVM * hvm);
void vm_start(void);
uint32_t init_control_field(uint32_t ctl, uint32_t msr);

#endif