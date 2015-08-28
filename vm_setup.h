#ifndef _VMCS_
#define _VMCS_

#include "vmx_api.h"

void vmcs_init(HVM * hvm);
void vm_start(void);

#endif