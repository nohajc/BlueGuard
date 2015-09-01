#include "lib_uefi.h"
#include "vmx_api.h"
#include "vmx_emu.h"
#include "regs.h"
#include "hv_handlers.h"
#include "string.h"
#include "smp.h"
#include "realmode_emu.h"

CHAR16 *reg_str[] = 
{
  L"RAX",
  L"RCX",
  L"RDX",
  L"RBX",
  L"RSP",
  L"RBP",
  L"RSI",
  L"RDI",
  L"R8",
  L"R9",
  L"R10",
  L"R11",
  L"R12",
  L"R13",
  L"R14",
  L"R15"
};

/*void handle_disable_paging(void){
  print(L"Paging disabled.");
}*/

void handle_mov_to_cr(GUEST_REGS * regs, uint8_t cr_num, uint8_t gp_reg){
  switch(cr_num){
    case 0:
      /*if(!( ((uint64_t*)regs)[gp_reg] & X86_CR0_PG )){
        handle_disable_paging();
      }*/
      regs->hvm->guest_CR0 = ((uint64_t*)regs)[gp_reg];
      if(regs->hvm->guest_CR0 & X86_CR0_PG){
        vmx_write(GUEST_CR3, regs->hvm->guest_CR3);
        if(regs->hvm->guest_EFER & EFER_LME){
          regs->hvm->guest_EFER |= EFER_LMA;
          vmx_write(VM_ENTRY_CONTROLS, vmx_read(VM_ENTRY_CONTROLS) | VM_ENTRY_IA32E_MODE);
        }
        else{
          regs->hvm->guest_EFER &= ~EFER_LMA;
          vmx_write(VM_ENTRY_CONTROLS, vmx_read(VM_ENTRY_CONTROLS) & ~VM_ENTRY_IA32E_MODE);
        }
      }

      vmx_write(CR0_READ_SHADOW, ((uint64_t*)regs)[gp_reg] & X86_CR0_PG);
      break;
    case 3:
      regs->hvm->guest_CR3 = ((uint64_t*)regs)[gp_reg];
      if(regs->hvm->guest_CR0 & X86_CR0_PG){
        vmx_write(GUEST_CR3, ((uint64_t*)regs)[gp_reg]);
      }
      break;
    case 4:
      mov_to_cr4:
      vmx_write(CR4_READ_SHADOW, ((uint64_t*)regs)[gp_reg] & X86_CR4_VMXE);
      regs->hvm->guest_CR4 = ((uint64_t*)regs)[gp_reg];
      vmx_write(GUEST_CR4, ((uint64_t*)regs)[gp_reg] | X86_CR4_VMXE);
      break;
    default:;
  }
}

void handle_mov_from_cr(GUEST_REGS * regs, uint8_t cr_num, uint8_t gp_reg){
  switch(cr_num){
    case 0:
      ((uint64_t*)regs)[gp_reg] = vmx_read(GUEST_CR0);
      break;
    case 3:
      //((uint64_t*)regs)[gp_reg] = vmx_read(GUEST_CR3);
      ((uint64_t*)regs)[gp_reg] = regs->hvm->guest_CR3;
      break;
    case 4:
      //((uint64_t*)regs)[gp_reg] = vmx_read(GUEST_CR4);
      ((uint64_t*)regs)[gp_reg] = regs->hvm->guest_CR4;
      break;
    default:;
  }
}

void handle_clts(GUEST_REGS * regs){
  //print(L"CLTS");
}

void handle_lmsw(GUEST_REGS * regs){
  //print(L"LMSW");
}

void handle_cr_access(GUEST_REGS * regs){
  uint64_t exit_qualification = vmx_read(EXIT_QUALIFICATION);
  uint8_t cr_num = exit_qualification & 0xF;
  uint8_t access_type = (exit_qualification >> 4) & 3;
  uint8_t gp_reg = (exit_qualification >> 8) & 0xF;

  //print(L"CR"); print_uint(cr_num); print(L"\r\n");

  switch(access_type){
    case 0:
      //print(L"MOV to CR from ");
      handle_mov_to_cr(regs, cr_num, gp_reg);
      break;
    case 1:
      //print(L"MOV from CR to ");
      handle_mov_from_cr(regs, cr_num, gp_reg);
      break;
    case 2:
      handle_clts(regs);
      break;
    case 3:
      handle_lmsw(regs);
      break;
    default:;
  }

  /*if(access_type < 2){
    print(reg_str[gp_reg]); print(L"\r\n");
  }*/
}

void handle_msr_read(GUEST_REGS * regs){
  uint64_t guest_param;

  switch(regs->rcx & 0xFFFFFFFF){
    case MSR_IA32_SYSENTER_CS:
      guest_param = vmx_read(GUEST_SYSENTER_CS);
      break;
    case MSR_IA32_SYSENTER_ESP:
      guest_param = vmx_read(GUEST_SYSENTER_ESP);
      break;
    case MSR_IA32_SYSENTER_EIP:
      guest_param = vmx_read(GUEST_SYSENTER_EIP);
      break;
    case MSR_FS_BASE:
      guest_param = vmx_read(GUEST_FS_BASE);
      break;
    case MSR_GS_BASE:
      guest_param = vmx_read(GUEST_GS_BASE);
      break;
    case MSR_EFER:
      guest_param = regs->hvm->guest_EFER;
      break;
    default:
      emu_rdmsr(regs->rcx, &regs->rdx, &regs->rax);
      return;
  }

  regs->rax = guest_param & 0xFFFFFFFF;
  regs->rdx = guest_param >> 32;
}

void handle_msr_break(uint64_t rdx, uint64_t rax){

}

void handle_msr_write(GUEST_REGS * regs){
  uint64_t guest_param = (regs->rax & 0xFFFFFFFF) | (regs->rdx << 32);

  switch(regs->rcx & 0xFFFFFFFF){
    case MSR_IA32_SYSENTER_CS:
      vmx_write(GUEST_SYSENTER_CS, guest_param);
      break;
    case MSR_IA32_SYSENTER_ESP:
      vmx_write(GUEST_SYSENTER_ESP, guest_param);
      break;
    case MSR_IA32_SYSENTER_EIP:
      vmx_write(GUEST_SYSENTER_EIP, guest_param);
      break;
    case MSR_FS_BASE:
      vmx_write(GUEST_FS_BASE, guest_param);
      break;
    case MSR_GS_BASE:
      vmx_write(GUEST_GS_BASE, guest_param);
      break;
    case MSR_EFER:
      regs->hvm->guest_EFER = (regs->rax & 0xFFFFFFFF) | (regs->rdx << 32);
      emu_wrmsr(regs->rcx, regs->rdx, (regs->rax & 0xFFFFFFFF) | EFER_LME);
      break;
    default:
      emu_wrmsr(regs->rcx, regs->rdx, (regs->rax & 0xFFFFFFFF));
  }
  
}

void debug_print(GUEST_REGS * regs){
  print(L"RAX: "); print_uintx(regs->rax); print(L"\r\n");
  print(L"RBX: "); print_uintx(regs->rbx); print(L"\r\n");
  print(L"RCX: "); print_uintx(regs->rcx); print(L"\r\n");
  print(L"RDX: "); print_uintx(regs->rdx); print(L"\r\n");
  print(L"RBP: "); print_uintx(regs->rbp); print(L"\r\n");
  print(L"RSI: "); print_uintx(regs->rsi); print(L"\r\n");
  print(L"RDI: "); print_uintx(regs->rdi); print(L"\r\n");
  print(L" R8: "); print_uintx(regs->r8); print(L"\r\n");
  print(L" R9: "); print_uintx(regs->r9); print(L"\r\n");
  print(L"R10: "); print_uintx(regs->r10); print(L"\r\n");
  print(L"R11: "); print_uintx(regs->r11); print(L"\r\n");
  print(L"R12: "); print_uintx(regs->r12); print(L"\r\n");
  print(L"R13: "); print_uintx(regs->r13); print(L"\r\n");
  print(L"R14: "); print_uintx(regs->r14); print(L"\r\n");
  print(L"R15: "); print_uintx(regs->r15); print(L"\r\n");
  print_uintx(regs->hvm->cpu_id);
}

void unknown_exit(uint64_t exit_reason){
  uint64_t exit_qualification =  vmx_read(EXIT_QUALIFICATION);
  /*print(L"Exit reason: ");
  print_uint(exit_reason & 0xFFFF);
  print(L"\r\n");*/
  print_err:
  return;
  /*bsp_printf("Unknown exit.\r\n");
  bsp_printf("Exit reason: %u\r\n", exit_reason & 0xFFFF);
  bsp_printf("Exit qualification: %u\r\n", exit_qualification);*/
}

void handle_failed_vmentry(uint64_t exit_reason){
  uint64_t exit_qualification =  vmx_read(EXIT_QUALIFICATION);

  print_err:
  bsp_printf("Failed vmentry.\r\n");
  bsp_printf("Exit reason: %u\r\n", exit_reason & 0xFFFF);
  bsp_printf("Exit qualification: %u\r\n", exit_qualification);
}

void handle_vmcall(GUEST_REGS * regs){
  regs->rax = 0x47415753; // "SWAG"
}

void handle_sipi(GUEST_REGS * regs){
  uint64_t exit_qualification = vmx_read(EXIT_QUALIFICATION);
  uint64_t seg = exit_qualification << 8;
  uint8_t * eip;
  if(!seg){ // VMware bug - EXIT_QUALIFICATION is always zero
    seg = 0x100;
  }

  eip = (uint8_t*)(seg << 4);

  vmx_write(GUEST_CS_SELECTOR, seg);
  vmx_write(VM_ENTRY_CONTROLS, vmx_read(VM_ENTRY_CONTROLS) & ~VM_ENTRY_IA32E_MODE);
  vmx_write(GUEST_CR4, regs->hvm->guest_CR4); // Disable PAE

  // TODO: provide 32bit page tables to the guest
  
  while(regs->hvm->guest_realsegment){ // Emulate the real mode trampoline execution
    exec_instruction(regs, &eip);
  }

  vmx_write(GUEST_EIP, (uint64_t)eip);
  vmx_write(GUEST_ESP, (uint64_t)ap_stacks + regs->hvm->cpu_id * 4096);

  //CopyMem((void*)regs->hvm->st->debug_area, &addr, 8);
  //print_uintx(addr);
  //vmx_write(GUEST_EIP, addr);
  resume_ap:
  //vmx_write(GUEST_ACTIVITY_STATE, STATE_HLT);
  vmx_write(GUEST_ACTIVITY_STATE, STATE_ACTIVE);
}

void vmexit_handler(GUEST_REGS * regs){
  // CPUID, GETSEC, INVD, MOV from/to CR3
  // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMREAD, VMRESUME, VMWRITE, VMXOFF, VMXON
  uint64_t exit_reason = vmx_read(VM_EXIT_REASON);
  uint64_t guest_rip, instr_len;

  //debug_print(regs);

  if(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY){
    handle_failed_vmentry(exit_reason);
    return;
  }

  switch(exit_reason){
    case EXIT_REASON_MSR_READ:
      handle_msr_read(regs);
      break;
    case EXIT_REASON_MSR_WRITE:
      handle_msr_write(regs);
      break;
    case EXIT_REASON_CR_ACCESS:
      handle_cr_access(regs);
      break;
    case EXIT_REASON_CPUID:
      emu_cpuid(&regs->rax, &regs->rbx, &regs->rcx, &regs->rdx);
      break;
    case EXIT_REASON_VMCALL:
      handle_vmcall(regs);
      break;
    case EXIT_REASON_SIPI:
      handle_sipi(regs);
      return;
    default:;
      unknown_exit(exit_reason & 0xFFFF);
  }

  guest_rip = vmx_read(GUEST_EIP);
  instr_len = vmx_read(VM_EXIT_INSTRUCTION_LEN);
  vmx_write(GUEST_EIP, guest_rip + instr_len);
}