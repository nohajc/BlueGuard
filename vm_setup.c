#include <efi.h>
#include <efilib.h>
#include <stdint.h>
#include "lib_uefi.h"
#include "vm_setup.h"
#include "regs.h"


void set_guest_selector(uint64_t gdt_base, uint32_t reg, uint64_t sel){
  uint64_t base;
  uint32_t limit;
  uint32_t attr;
  GDT_ENTRY * entry;

  entry = (GDT_ENTRY*)((uint64_t)gdt_base + (sel & ~0x7));
  base = entry->base_0_15 | entry->base_16_23 << 16 | entry->base_24_31 << 24;

  /*if(reg == TR){
    print(L"DEBUG TR_SEL "); print_uintx(sel & ~0x7); print(L"\r\n");
    print(L"DEBUG TR_BASE "); print_uint(base); print(L"\r\n");
  }*/

  limit = entry->limit_0_15 | (entry->limit_16_19_attr_8_11 & 0xF) << 16;
  attr = entry->attr_0_7 | (entry->limit_16_19_attr_8_11 & 0xF0) << 8;

  if(!(attr & 0x10)){ // non standard entry - callgate/TSS 
    base |= *((uint64_t*)entry + 1) << 32; // save the high part of base
  }

  if(attr & 0x8000){ // g bit set
    limit = (limit << 12) | 0xFFF; // scale the limit
  }

  if(!sel){
    attr |= 0x10000; // "unusable segment" valid in 64-bit mode only
  }

  if(reg <= DS){
    vmx_write(GUEST_ES_BASE + (reg << 1), 0);
  }
  else if(reg == FS){
    vmx_write(GUEST_FS_BASE, get_msr(MSR_FS_BASE));
  }
  else if(reg == GS){
    vmx_write(GUEST_GS_BASE, get_msr(MSR_GS_BASE));
  }
  else{ // LDTR, TR
    vmx_write(GUEST_ES_BASE + (reg << 1), base);
  }

  vmx_write(GUEST_ES_SELECTOR + (reg << 1), sel);
  vmx_write(GUEST_ES_LIMIT + (reg << 1), limit);
  vmx_write(GUEST_ES_AR_BYTES + (reg << 1), attr);
}

uint32_t init_control_field(uint32_t ctl, uint32_t msr){
  union{
    uint64_t qword;
    struct{
      uint32_t low;
      uint32_t high;
    } dword;
  } mask;

  mask.qword = get_msr(msr);
  ctl &= mask.dword.high;
  ctl |= mask.dword.low;

  return ctl;
}

void vm_start(void){
  uint64_t error_code;

  vmx_write(GUEST_ESP, get_rbp());
  vmx_write(GUEST_EIP, (uint64_t)vmx_ret);

  vmx_launch();

  print(L"VMLAUNCH failed.\r\nError code: ");
  error_code = vmx_read(VM_INSTRUCTION_ERROR);
  print_uint(error_code);
  print(L"\r\n");
}

void vmcs_init(HVM * hvm){
  uint64_t cr0, cr3, cr4, sysenter_cs, sysenter_esp, sysenter_eip, debugctl;
  uint64_t base = (uint64_t)hvm->st->gdt_base;
  uint64_t tr_sel = hvm->st->tr_sel;
  uint64_t tss_base = (uint64_t)hvm->st->tss_base;
  //EFI_STATUS st;
  
  vmx_write(HOST_IDTR_BASE, hvm->st->idt_base);
  vmx_write(GUEST_IDTR_BASE, hvm->st->idt_base);
  vmx_write(GUEST_IDTR_LIMIT, hvm->st->idt_limit);

  vmx_write(HOST_ES_SELECTOR, get_es() & 0xf8);
  vmx_write(HOST_CS_SELECTOR, get_cs() & 0xf8);
  vmx_write(HOST_SS_SELECTOR, get_ss() & 0xf8);
  vmx_write(HOST_DS_SELECTOR, get_ds() & 0xf8);
  vmx_write(HOST_FS_SELECTOR, get_fs() & 0xf8);
  vmx_write(HOST_GS_SELECTOR, get_gs() & 0xf8);
  vmx_write(HOST_TR_SELECTOR, tr_sel & 0xf8);

  vmx_write(HOST_GDTR_BASE, hvm->st->gdt_base);
  vmx_write(GUEST_GDTR_BASE, hvm->st->gdt_base);
  vmx_write(GUEST_GDTR_LIMIT, hvm->st->gdt_limit);

  vmx_write(GUEST_INTERRUPTIBILITY_INFO, 0);
  vmx_write(GUEST_ACTIVITY_STATE, STATE_ACTIVE);

  vmx_write(CR0_GUEST_HOST_MASK, X86_CR0_PG);
  vmx_write(CR4_GUEST_HOST_MASK, X86_CR4_VMXE); //disable vmexit 0f mov to cr4 except for X86_CR4_VMXE

  vmx_write(CR0_READ_SHADOW, (get_cr4 () & X86_CR0_PG) | X86_CR0_PG);

  vmx_write(CR4_READ_SHADOW, 0);
  vmx_write(CR3_TARGET_VALUE0, 0);      //no use
  vmx_write(CR3_TARGET_VALUE1, 0);      //no use                        
  vmx_write(CR3_TARGET_VALUE2, 0);      //no use
  vmx_write(CR3_TARGET_VALUE3, 0);      //no use

  /*print(L"ES_SELECTOR: "); print_uintx(get_es()); print(L"\r\n");
  print(L"CS_SELECTOR: "); print_uintx(get_cs()); print(L"\r\n");
  print(L"SS_SELECTOR: "); print_uintx(get_ss()); print(L"\r\n");
  print(L"DS_SELECTOR: "); print_uintx(get_ds()); print(L"\r\n");
  print(L"FS_SELECTOR: "); print_uintx(get_fs()); print(L"\r\n");
  print(L"GS_SELECTOR: "); print_uintx(get_gs()); print(L"\r\n");
  print(L"TR_SELECTOR: "); print_uintx(tr_sel); print(L"\r\n");*/

  set_guest_selector(base, ES, get_es());
  set_guest_selector(base, CS, get_cs());
  set_guest_selector(base, SS, get_ss());
  set_guest_selector(base, DS, get_ds());
  set_guest_selector(base, FS, get_fs());
  set_guest_selector(base, GS, get_gs());
  set_guest_selector(base, LDTR, get_ldtr());
  set_guest_selector(base, TR, tr_sel);


  cr0 = get_cr0();
  cr3 = get_cr3();
  cr4 = get_cr4();

    
  vmx_write(HOST_CR0, cr0);
  vmx_write(GUEST_CR0, cr0);
  vmx_write(HOST_CR3, hvm->st->host_cr3);
  vmx_write(GUEST_CR3, cr3);
  vmx_write(HOST_CR4, cr4);
  vmx_write(GUEST_CR4, cr4);

  vmx_write(GUEST_DR7, 0x400);
  vmx_write(GUEST_EFLAGS, get_rflags());

  sysenter_cs = get_msr(MSR_IA32_SYSENTER_CS);
  vmx_write(GUEST_SYSENTER_CS, sysenter_cs);
  vmx_write(HOST_IA32_SYSENTER_CS, sysenter_cs);

  sysenter_esp = get_msr(MSR_IA32_SYSENTER_ESP);
  vmx_write(GUEST_SYSENTER_ESP, sysenter_esp);
  vmx_write(HOST_IA32_SYSENTER_ESP, sysenter_esp);

  //print(L"SYSENTER_ESP: "); print_uint(sysenter_esp); print(L"\r\n");

  sysenter_eip = get_msr(MSR_IA32_SYSENTER_EIP);
  vmx_write(GUEST_SYSENTER_EIP, sysenter_eip);
  vmx_write(HOST_IA32_SYSENTER_EIP, sysenter_eip);

  //print(L"SYSENTER_EIP: "); print_uint(sysenter_eip); print(L"\r\n");

  vmx_write(VMCS_LINK_POINTER, 0xFFFFFFFF);
  vmx_write(VMCS_LINK_POINTER_HIGH, 0xFFFFFFFF);

  debugctl = get_msr(MSR_IA32_DEBUGCTL);
  vmx_write(GUEST_IA32_DEBUGCTL, debugctl & 0xFFFFFFFF);
  vmx_write(GUEST_IA32_DEBUGCTL_HIGH, debugctl >> 32);

  vmx_write(HOST_FS_BASE, get_msr(MSR_FS_BASE));
  vmx_write(HOST_GS_BASE, get_msr(MSR_GS_BASE));

  //entry = (GDT_ENTRY*)((uint64_t)base + (get_tr() & ~0x7));
  //tr_base = entry->base_0_15 | entry->base_16_23 << 16 | entry->base_24_31 << 24;
  vmx_write(HOST_TR_BASE, tss_base);

  /*print(L"HOST_FS_BASE: "); print_uint(get_msr(MSR_FS_BASE)); print(L"\r\n");
  print(L"HOST_GS_BASE: "); print_uint(get_msr(MSR_GS_BASE)); print(L"\r\n");
  print(L"HOST_TR_BASE: "); print_uint(tr_base); print(L"\r\n");*/

  // Put pointer to the HVM structure onto the host stack
  // It will end up as the last element of GUEST_REGS structure
  *(HVM**)(hvm->host_stack + 0xFFF8) = hvm;

  vmx_write(HOST_ESP, hvm->host_stack + 0xFFF8);
  //vmx_write(HOST_EIP, (uint64_t)ptr_vmx_exit);
  vmx_write(HOST_EIP, (uint64_t)vmx_exit);

  /*vmx_write(IO_BITMAP_A, hvm->io_bitmap_a & 0xFFFFFFFF);
  vmx_write(IO_BITMAP_A_HIGH, hvm->io_bitmap_a >> 32);

  vmx_write(IO_BITMAP_B, hvm->io_bitmap_b & 0xFFFFFFFF);
  vmx_write(IO_BITMAP_B_HIGH, hvm->io_bitmap_b >> 32);

  vmx_write(MSR_BITMAP, hvm->msr_bitmap & 0xFFFFFFFF);
  vmx_write(MSR_BITMAP_HIGH, hvm->msr_bitmap >> 32);*/

  /*vmx_write(TSC_OFFSET, 0);
  vmx_write(TSC_OFFSET_HIGH, 0);*/

  //disable Vmexit by Extern-interrupt,NMI and Virtual NMI
  vmx_write(PIN_BASED_VM_EXEC_CONTROL, init_control_field(0, MSR_IA32_VMX_PINBASED_CTLS));

  //CPU_BASED_ACTIVATE_MSR_BITMAP
  vmx_write(PRIMARY_CPU_BASED_VM_EXEC_CONTROL, init_control_field(0, MSR_IA32_VMX_PROCBASED_CTLS));
  //print(L"CPU_BASED_VM_EXEC_CONTROL: "); print_uintb(vmx_read(PRIMARY_CPU_BASED_VM_EXEC_CONTROL)); print(L"\r\n");

  vmx_write(VM_EXIT_CONTROLS, init_control_field(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
  vmx_write(VM_ENTRY_CONTROLS, init_control_field(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

  vmx_write(PAGE_FAULT_ERROR_CODE_MASK, 0);
  vmx_write(PAGE_FAULT_ERROR_CODE_MATCH, 0);
  vmx_write(CR3_TARGET_COUNT, 0);

  vmx_write(VM_EXIT_MSR_STORE_COUNT, 0);
  vmx_write(VM_EXIT_MSR_LOAD_COUNT, 0);
  vmx_write(VM_ENTRY_MSR_LOAD_COUNT, 0);
  vmx_write(VM_ENTRY_INTR_INFO_FIELD, 0);

  hvm->guest_EFER = get_msr(MSR_EFER);

  //print(L"DEBUG:\r\n");
  //print(L"CR0: "); print_uintb(get_cr0()); print(L"\r\n");
  //print(L"CR0 FIXED0: "); print_uintb(get_msr(MSR_IA32_VMX_CR0_FIXED0)); print(L"\r\n");
  //print(L"CR0 FIXED1: "); print_uintb(get_msr(MSR_IA32_VMX_CR0_FIXED1)); print(L"\r\n\n");

  //print(L"CR3: "); print_uintb(get_cr3()); print(L"\r\n");
  //print(L"CR4: "); print_uintb(get_cr4()); print(L"\r\n");
  //print(L"CR4 FIXED0: "); print_uintb(get_msr(MSR_IA32_VMX_CR4_FIXED0)); print(L"\r\n");
  //print(L"CR4 FIXED1: "); print_uintb(get_msr(MSR_IA32_VMX_CR4_FIXED1)); print(L"\r\n\n");
  /*print(L"Guest TR Selector: "); print_uintx(vmx_read(GUEST_TR_SELECTOR)); print(L"\r\n");
  print(L"Guest LDTR Selector: "); print_uintx(vmx_read(GUEST_LDTR_SELECTOR)); print(L"\r\n");
  print(L"Guest TR Base: "); print_uintx(vmx_read(GUEST_TR_BASE)); print(L"\r\n");
  print(L"Guest FS Base: "); print_uintx(vmx_read(GUEST_FS_BASE)); print(L"\r\n");
  print(L"Guest GS Base: "); print_uintx(vmx_read(GUEST_GS_BASE)); print(L"\r\n");
  print(L"Guest CS Base: "); print_uintx(vmx_read(GUEST_CS_BASE)); print(L"\r\n");
  print(L"Guest SS Base: "); print_uintx(vmx_read(GUEST_SS_BASE)); print(L"\r\n");
  print(L"Guest DS Base: "); print_uintx(vmx_read(GUEST_DS_BASE)); print(L"\r\n");
  print(L"Guest ES Base: "); print_uintx(vmx_read(GUEST_ES_BASE)); print(L"\r\n");*/

  /*print(L"Guest TR AR bytes: "); print_uintx(vmx_read(GUEST_TR_AR_BYTES)); print(L"\r\n");
  print(L"Guest LDTR AR bytes: "); print_uintx(vmx_read(GUEST_LDTR_AR_BYTES)); print(L"\r\n");
  print(L"Guest CS AR bytes: "); print_uintx(vmx_read(GUEST_CS_AR_BYTES)); print(L"\r\n");
  print(L"Guest SS AR bytes: "); print_uintx(vmx_read(GUEST_SS_AR_BYTES)); print(L"\r\n");
  print(L"Guest DS AR bytes: "); print_uintx(vmx_read(GUEST_DS_AR_BYTES)); print(L"\r\n");
  print(L"Guest ES AR bytes: "); print_uintx(vmx_read(GUEST_ES_AR_BYTES)); print(L"\r\n");
  print(L"Guest FS AR bytes: "); print_uintx(vmx_read(GUEST_FS_AR_BYTES)); print(L"\r\n");
  print(L"Guest GS AR bytes: "); print_uintx(vmx_read(GUEST_GS_AR_BYTES)); print(L"\r\n");

  print(L"Guest TR limit: "); print_uintx(vmx_read(GUEST_TR_LIMIT)); print(L"\r\n");
  print(L"Guest LDTR limit: "); print_uintx(vmx_read(GUEST_LDTR_LIMIT)); print(L"\r\n");
  print(L"Guest CS limit: "); print_uintx(vmx_read(GUEST_CS_LIMIT)); print(L"\r\n");
  print(L"Guest SS limit: "); print_uintx(vmx_read(GUEST_SS_LIMIT)); print(L"\r\n");
  print(L"Guest DS limit: "); print_uintx(vmx_read(GUEST_DS_LIMIT)); print(L"\r\n");
  print(L"Guest ES limit: "); print_uintx(vmx_read(GUEST_ES_LIMIT)); print(L"\r\n");
  print(L"Guest FS limit: "); print_uintx(vmx_read(GUEST_FS_LIMIT)); print(L"\r\n");
  print(L"Guest GS limit: "); print_uintx(vmx_read(GUEST_GS_LIMIT)); print(L"\r\n");*/
}