#include "regs.h"
#include "vmx_api.h"

int vmx_guest_efer_supported(void){
	uint64_t entry_ctls = get_msr(MSR_IA32_VMX_ENTRY_CTLS);
	uint64_t exit_ctls = get_msr(MSR_IA32_VMX_EXIT_CTLS);

	if(entry_ctls & (1ULL << 55)){
		entry_ctls = get_msr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
	}
	if(exit_ctls & (1ULL << 55)){
		exit_ctls = get_msr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
	}

	return (entry_ctls & (1ULL << 47)) && (exit_ctls & (1ULL << 52));
}