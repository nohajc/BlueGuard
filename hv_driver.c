#include <efi.h>
#include <efilib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lib_uefi.h"
#include "vmx_api.h"
#include "vmx_emu.h"
#include "regs.h"
#include "hv_handlers.h"
#include "reloc_pe.h"
#include "smp.h"
#include "string.h"


CHAR16 magic[] = L"MAGIC_COMM_YOLO";
char hello[] = "OH HI, MARK. I'M YOUR EFI DRIVER!";

typedef
EFI_STATUS
(EFIAPI *EFI_GET_VARIABLE)(
  IN     CHAR16   *VariableName,
  IN     EFI_GUID *VendorGuid,
  OUT    UINT32   *Attributes OPTIONAL,
  IN OUT UINTN    *DataSize,
  OUT    VOID     *Data
);

EFI_GET_VARIABLE GetVariableOrig;

EFI_STATUS GetVariableHook(
  IN     CHAR16   *VariableName,
  IN     EFI_GUID *VendorGuid,
  OUT    UINT32   *Attributes OPTIONAL,
  IN OUT UINTN    *DataSize,
  OUT    VOID     *Data
){
    if(!strcmp(VariableName, magic)){
        CopyMem(Data, hello, sizeof(hello));
        //TODO: set data size
        *DataSize = sizeof(hello);

        return EFI_SUCCESS;
    }
    else{
        return GetVariableOrig(VariableName, VendorGuid, Attributes, DataSize, Data);
    }
}

typedef
EFI_STATUS
(EFIAPI *EFI_SET_VIRTUAL_ADDRESS_MAP)(
  IN UINTN MemoryMapSize,
  IN UINTN DescriptorSize,
  IN UINT32 DescriptorVersion,
  IN EFI_MEMORY_DESCRIPTOR *VirtualMap
);

EFI_SET_VIRTUAL_ADDRESS_MAP SetVirtualAddressMapOrig;

EFI_STATUS SetVirtualAddressMapHook(
  IN UINTN MemoryMapSize,
  IN UINTN DescriptorSize,
  IN UINT32 DescriptorVersion,
  IN EFI_MEMORY_DESCRIPTOR *VirtualMap
){
  EFI_STATUS st = SetVirtualAddressMapOrig(MemoryMapSize, DescriptorSize, DescriptorVersion, VirtualMap);
  unknown_exit(0);
  return st;
}


EFI_EVENT evt;

VOID callback(IN EFI_EVENT Event, IN VOID * Contex)
{
    RT->ConvertPointer(0, (VOID**)&RT->GetVariable);
    RT->ConvertPointer(0, (VOID**)&GetVariableOrig);
}


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

void setup_tss_descriptor(HVM * hvm){
  GDT_ENTRY * entry;
  SharedTables * st = hvm->st;
  uint64_t tss_base = st->tss_base;
  uint32_t tss_limit = 103;
  uint64_t idx = st->gdt_limit + 1;

  entry = (GDT_ENTRY*)(st->gdt_base + idx);

  entry->attr_0_7 = 0x8B; // 0b1000 - present, 0b1011 - 64-bit TSS (Busy)
  //entry->attr_0_7 = 0x89; // 0b1000 - present, 0b1001 - 64-bit TSS (Available)
  entry->limit_16_19_attr_8_11 = (tss_limit >> 16) & 0xF;
  entry->limit_0_15 = tss_limit & 0xFFFF;
  *(uint8_t*)((uint64_t)entry + 13) &= ~0x1F;
  entry->base_0_15 = tss_base & 0xFFFF;
  entry->base_16_23 = (tss_base >> 16) & 0xFF;
  entry->base_24_31 = (tss_base >> 24) & 0xFF;
  *(uint32_t*)((uint64_t)entry + 8) = tss_base >> 32;
  //print(L"base_0_15: "); print_uint(entry->base_0_15); print(L"\r\n");

  //set_gdt_base_limit(new_gdt_base, idx - 1 + 16);
  //set_tr(idx);
  st->gdt_limit += 16;
  st->tr_sel = idx;
}


uint64_t copy_pt(uint64_t pt){
  EFI_STATUS st;
  uint64_t * pt_entry = (uint64_t*)pt;
  uint64_t * copied_pt_entry = (uint64_t*)0xFFFFFFFF;

  st = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, 1, (EFI_PHYSICAL_ADDRESS*)&copied_pt_entry);
  if(st != EFI_SUCCESS){
    print(L"PT ALLOC ERROR!\r\n");
    return 0;
  }

  CopyMem(copied_pt_entry, pt_entry, 4096);
  return (uint64_t)copied_pt_entry;
}

uint64_t copy_pdt(uint64_t pdt){
  EFI_STATUS st;
  int i;
  uint64_t * pdt_entry = (uint64_t*)pdt;
  uint64_t * copied_pdt_entry = (uint64_t*)0xFFFFFFFF;
  uint64_t addr, copied_addr;

  st = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, 1, (EFI_PHYSICAL_ADDRESS*)&copied_pdt_entry);
  if(st != EFI_SUCCESS){
    print(L"PDT ALLOC ERROR!\r\n");
    return 0;
  }

  for(i = 0; i < 512; ++i){
    if((pdt_entry[i] & PG_PRESENT) && !(pdt_entry[i] & PG_SIZE)){
      addr = pdt_entry[i] & ~0xFFF;
      copied_addr = copy_pt(addr);
      if(!copied_addr) return 0;
      copied_pdt_entry[i] = copied_addr | (pdt_entry[i] & 0xFFF);
    }
    else{
      copied_pdt_entry[i] = pdt_entry[i];
    }
  }

  return (uint64_t)copied_pdt_entry;
}

uint64_t copy_pdpt(uint64_t pdpt){
  EFI_STATUS st;
  int i;
  uint64_t * pdpt_entry = (uint64_t*)pdpt;
  uint64_t * copied_pdpt_entry = (uint64_t*)0xFFFFFFFF;
  uint64_t addr, copied_addr;

  st = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, 1, (EFI_PHYSICAL_ADDRESS*)&copied_pdpt_entry);
  if(st != EFI_SUCCESS){
    print(L"PDPT ALLOC ERROR!\r\n");
    return 0;
  }
  //print(L"Allocated new PDPT\r\n");

  for(i = 0; i < 512; ++i){
    if((pdpt_entry[i] & PG_PRESENT) && !(pdpt_entry[i] & PG_SIZE)){
      addr = pdpt_entry[i] & ~0xFFF;
      copied_addr = copy_pdt(addr);
      if(!copied_addr) return 0;
      copied_pdpt_entry[i] = copied_addr | (pdpt_entry[i] & 0xFFF);
    }
    else{
      copied_pdpt_entry[i] = pdpt_entry[i];
    }
  }

  return (uint64_t)copied_pdpt_entry;
}

uint64_t copy_page_tables(uint64_t pml4t){
  EFI_STATUS st;
  int i;
  uint64_t * pml4t_entry = (uint64_t*)pml4t;
  uint64_t * copied_pml4t_entry = (uint64_t*)0xFFFFFFFF;
  uint64_t addr, copied_addr;

  st = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, 1, (EFI_PHYSICAL_ADDRESS*)&copied_pml4t_entry);
  if(st != EFI_SUCCESS){
    print(L"PML4T ALLOC ERROR!\r\n");
    return 0;
  }
  //print(L"Allocated new PML4T\r\n");

  for(i = 0; i < 512; ++i){
    if(pml4t_entry[i] & PG_PRESENT){
      addr = pml4t_entry[i] & ~0xFFF;
      copied_addr = copy_pdpt(addr);
      if(!copied_addr) return 0;
      copied_pml4t_entry[i] = copied_addr | (pml4t_entry[i] & 0xFFF);
    }
    else{
      copied_pml4t_entry[i] = pml4t_entry[i];
    }
  }

  return (uint64_t)copied_pml4t_entry;
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
  vmx_write(GUEST_ACTIVITY_STATE, 0);

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

int migrate_image(EFI_LOADED_IMAGE * loaded_image){
  EFI_STATUS st;
  int img_pages = loaded_image->ImageSize / 4096 + !!(loaded_image->ImageSize % 4096);
  uint64_t new_img_base;
  int64_t delta;

  st = BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode, img_pages, (EFI_PHYSICAL_ADDRESS*)&new_img_base);
  if(st != EFI_SUCCESS){
    return 0;
  }

  CopyMem((void*)new_img_base + 0x1000, loaded_image->ImageBase + 0x1000, loaded_image->ImageSize - 0x1000);

  delta = new_img_base - (int64_t)loaded_image->ImageBase;
  /*print(L"vmx_exit: "); print_uintx((uint64_t)vmx_exit); print(L"\r\n");
  print(L"OLD BASE: "); print_uintx((uint64_t)loaded_image->ImageBase); print(L"\r\n");
  print(L"NEW BASE: "); print_uintx(new_img_base); print(L"\r\n");*/

  // Create pointers to several copied functions
  ptr_vmexit_handler = (vmexit_handler_func)((int64_t)vmexit_handler + delta);
  ptr_vmx_exit = (vmx_exit_func)((int64_t)vmx_exit + delta);
  ptr_unknown_exit = (unknown_exit_func)((int64_t)unknown_exit + delta);
  ptr_handle_msr_break = (handle_msr_break_func)((int64_t)handle_msr_break + delta);


  reloc_image(loaded_image->ImageBase, new_img_base);

  //print(L"Size of image [UEFI]: "); print_uint(loaded_image->ImageSize); print(L"\r\n");
  return 1;
}

int prepare_shared_hvm_tables(HVM * hvm){
  EFI_STATUS err;
  uint64_t base;
  uint16_t limit;
  uint64_t cr3 = get_cr3();
  SharedTables * st = hvm->st;
  
  // Copy IDT
  get_idt_base_limit(&base, &limit);

  err = BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 3, &st->idt_base);
  if(err != EFI_SUCCESS){
    return 0;
  }

  CopyMem((void*)st->idt_base, (void*)base, limit + 1);
  //print(L"IDT LIMIT: "); print_uint(limit); print(L"\r\n");
  st->idt_limit = limit;

  // Copy GDT  
  get_gdt_base_limit(&base, &limit);

  st->gdt_base = st->idt_base + 4096;
  CopyMem((void*)st->gdt_base, (void*)base, limit + 1);
  st->gdt_limit = limit;

  // Create TSS
  st->tss_base = st->gdt_base + 4096;
  ZeroMem((void*)st->tss_base, 104);
  // *(uint64_t*)st->tss_base = get_rsp();

  st->tr_sel = limit + 1;
  setup_tss_descriptor(hvm);

  // !! WE NEED TO COPY ALL PAGE TABLES TO EfiRuntimeServicesData MEMORY
  // !! THE FIRMWARE HAS NO USE FOR THE IDENTITY MAPPING AFTER SetVirtualAddressMap() CALL
  // !! SO THE BOOTING OS WILL MOST LIKELY OVERWRITE THE ORIGINAL TABLES CAUSING PAGE FAULT ON VMEXIT
  st->host_cr3 = copy_page_tables(cr3 & ~0xFFF);
  if(!st->host_cr3){
    print(L"COPY PAGE TABLES ERROR!\r\n");
  }
  st->host_cr3 |= cr3 & 0xFFF;

  return 1;
}

HVM * bsp_hvm;
HVM * ap_hvm;

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE * sys_table)
{
    uint32_t vmx_rev, struct_size;
    EFI_STATUS st = EFI_SUCCESS;
    EFI_LOADED_IMAGE * loaded_image;
    int i;

    init(image, sys_table);
    init_smp();

    /*GetVariableOrig = RT->GetVariable;
    RT->GetVariable = GetVariableHook;*/
    SetVirtualAddressMapOrig = RT->SetVirtualAddressMap;
    RT->SetVirtualAddressMap = SetVirtualAddressMapHook;

    if(vmx_supported()){
        print(L"VMX is supported!\r\n");
    }
    else{
        print(L"Error: VMX is not supported.\r\n");
        goto epilog;
    }

    vmx_get_revision_and_struct_size(&vmx_rev, &struct_size);

    print(L"VMX revision: ");
    print_uint(vmx_rev);
    print(L"\r\n");
    print(L"Struct size: ");
    print_uint(struct_size);
    print(L"\r\n");

    // Prepare runtime memory for HVM
    st = BS->AllocatePool(EfiRuntimeServicesData, sizeof(HVM), (void**)&bsp_hvm);
    if(st != EFI_SUCCESS){
      goto epilog;
    }

    bsp_hvm->magic = 0xBEAF1BAF;
    bsp_hvm->st = (SharedTables*)((uint64_t)bsp_hvm + sizeof(HVM));
    //printf("HVM + ST size: %u\r\n", sizeof(HVM)+sizeof(SharedTables));

    st = BS->AllocatePool(EfiRuntimeServicesData, CPU_count * sizeof(HVM), (void**)&ap_hvm);
    if(st != EFI_SUCCESS){
      print(L"ap_hvm allocation error\r\n");
      goto epilog;
    }
    
    st = BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, CPU_count, &bsp_hvm->vmxon_region);
    if(st != EFI_SUCCESS){
      print(L"vmcs allocation error\r\n");
      goto epilog;
    }

    st = BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, CPU_count, &bsp_hvm->vmcs);
    if(st != EFI_SUCCESS){
      goto epilog;
    }

    st = BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 16 * CPU_count, &bsp_hvm->host_stack);
    if(st != EFI_SUCCESS){
      print(L"host stack allocation error\r\n");
      goto epilog;
    }

    for(i = 1; i < CPU_count; ++i){
      ap_hvm[i].st = bsp_hvm->st;
      ap_hvm[i].vmxon_region = (uint64_t)bsp_hvm->vmxon_region + i * 4096;
      ap_hvm[i].vmcs = (uint64_t)bsp_hvm->vmcs + i * 4096;
      ap_hvm[i].host_stack = (uint64_t)bsp_hvm->host_stack + i * 65536;
    }

    if(!prepare_shared_hvm_tables(bsp_hvm)){
      print(L"Error preparing shared hvm tables.\r\n");
    }

    // Start the rest of CPUs
    start_smp();

    print(L"Allocated VMXON-region at ");
    print_uint((uint64_t)bsp_hvm->vmxon_region);
    print(L"\r\n");

    // Write revision ID at the start of VMXON-region
    *(uint32_t*)bsp_hvm->vmxon_region = vmx_rev;

    vmx_enable(); // Set bit 13 of CR4 to 1 to enable the VMX operations
    //vmx_disable_a20_line();

    if(vmx_switch_to_root_op((void*)bsp_hvm->vmxon_region)){
      print(L"Switched to VMX-root-operation mode!\r\n");
    }
    else{
      print(L"Error switching to VMX-root-operation mode.\r\n");
      goto epilog;
    }

    *(uint32_t*)bsp_hvm->vmcs = vmx_rev;
    if(vmx_vmcs_activate((void*)bsp_hvm->vmcs)){
      print(L"Activated VMCS!\r\n");
    }
    else{
      print(L"Error activating VMCS.\r\n");
      goto epilog;
    }

    
    st = BS->OpenProtocol(image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if(EFI_ERROR(st)){
      print(L"Error getting a LoadedImageProtocol handle.\r\n");
      goto epilog;
    }

    migrate_image(loaded_image);

    //print(L"HOST_CR3: "); print_uintx(get_cr3()); print(L"\r\n");

    vmcs_init(bsp_hvm);
    //print(L"GUEST_CR3: "); print_uintx(vmx_read(GUEST_CR3)); print(L"\r\n");
    vm_start();
    print(L"Hello from the Guest VM!\r\n");
    //print(L"GUEST_CR3: "); print_uintx(get_cr3()); print(L"\r\n");

    //vmx_enable_a20_line();

    epilog:
    //BS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_CALLBACK, callback, NULL, &evt);
    return st;
}
