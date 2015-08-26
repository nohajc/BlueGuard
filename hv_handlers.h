#ifndef _HV_HANDLERS_
#define _HV_HANDLERS_


typedef void (*vmexit_handler_func)(GUEST_REGS * regs);
typedef void (*vmx_exit_func)(void);
typedef void (*unknown_exit_func)(uint64_t exit_reason);
typedef void (*handle_msr_break_func)(uint64_t rdx, uint64_t rax);

vmexit_handler_func ptr_vmexit_handler;
vmx_exit_func ptr_vmx_exit;
unknown_exit_func ptr_unknown_exit;
handle_msr_break_func ptr_handle_msr_break;

void vmexit_handler(GUEST_REGS * regs);
void vmx_exit(void);
void unknown_exit(uint64_t exit_reason);
void handle_msr_break(uint64_t rdx, uint64_t rax);

#endif