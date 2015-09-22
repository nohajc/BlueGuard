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
#include "vm_setup.h"
#include "realmode_emu.h"


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
  uint64_t rax, rbx, rcx, rdx;
  uint32_t i;
  
  // Copy IDT
  get_idt_base_limit(&base, &limit);

  st->idt_base = 0xFFFFFFFF;

  err = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, 3, &st->idt_base);
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

  st->tr_sel = get_tr();
  if(st->tr_sel != 0){
    print(L"We have TSS already!\r\n");
  }
  else{
    // Create TSS
    st->tss_base = st->gdt_base + 4096;
    ZeroMem((void*)st->tss_base, 104);
    *(uint64_t*)st->tss_base = get_rsp();

    st->tr_sel = limit + 1;
    setup_tss_descriptor(hvm);
  }

  // !! WE NEED TO COPY ALL PAGE TABLES TO EfiRuntimeServicesData MEMORY
  // !! THE FIRMWARE HAS NO USE FOR THE IDENTITY MAPPING AFTER SetVirtualAddressMap() CALL
  // !! SO THE BOOTING OS WILL MOST LIKELY OVERWRITE THE ORIGINAL TABLES CAUSING PAGE FAULT ON VMEXIT
  st->host_cr3 = copy_page_tables(cr3 & ~0xFFF);
  if(!st->host_cr3){
    print(L"COPY PAGE TABLES ERROR!\r\n");
  }
  st->host_cr3 |= cr3 & 0xFFF;

  err = BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &st->debug_area);
  if(err != EFI_SUCCESS){
    return 0;
  }

  ZeroMem((void*)st->debug_area, 4096);

  rax = 1;
  emu_cpuid(&rax, &rbx, &rcx, &rdx);
  //printf("CPUID.01H:EDX = %b\r\n", rdx);
  if(rdx & CPUID_PSE){ // 4 MB pages supported in 32 bit
    features.pse = true;
    //printf("Host CR3: %b\r\n", get_cr3());
    //printf("PML4TE: %b\r\n", *(uint64_t*)(get_cr3() & ~0xFFF));

    st->guest_cr3_32bit = 0xFFFFFFFF;
    err = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, 1, &st->guest_cr3_32bit);
    if(err != EFI_SUCCESS){
      return 0;
    }

    uint32_t * pde = (uint32_t*)st->guest_cr3_32bit;
    for(i = 0; i < 1024; ++i){
      pde[i] = (i << 22) | 0x83; // 7 (PS), 1 (R/W), 0 (P)
    }
  }
  else{
    features.pse = false;
    // TODO: Alloc and init classic 4 KB page tables
  }


  uint64_t ept_area_size;
  uint64_t ept_capabilities = get_msr(MSR_IA32_VMX_EPT_VPID_CAP);
  features.ept_cap_2MB_page = ept_capabilities & 0x10000;
  features.ept_cap_1GB_page = ept_capabilities & 0x20000;

  if(features.ept_cap_1GB_page){
    ept_area_size = 1 + 512;
  }
  else if(features.ept_cap_2MB_page){
    ept_area_size = 1 + 512 + 512 * 512;
  }

  st->ept_area = 0xFFFFFFFF;
  err = BS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, ept_area_size, &st->ept_area); // Space for EPT PML4T and 512 PDPTs
  if(err != EFI_SUCCESS){
    return 0;
  }

  //ZeroMem((void*)st->ept_area, ept_area_size * 4096);
  uint64_t * ept_ptr = (uint64_t*)st->ept_area;
  uint64_t * ept_end = ept_ptr + ept_area_size * 512;
  while(ept_ptr != ept_end){
    *ept_ptr++ = 0;
  }


  //printf("Debug area: %x\r\n", st->debug_area);

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

    if(vmx_ug_supported()){
        printf("VMX Unrestricted Guest supported!\r\n");
    }
    else{
        printf("Error: VMX Unrestricted Guest not supported.\r\n");
        goto epilog;
    }

    if(vmx_ept_supported()){
        printf("VMX EPT supported!\r\n");
    }
    else{
        printf("Error: VMX EPT not supported.\r\n");
        goto epilog;
    }

    if(vmx_vpid_supported()){
        printf("VMX VPID supported!\r\n");
    }
    else{
        printf("Error: VMX EPT not supported.\r\n");
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

    //bsp_hvm->magic = 0xBEAF1BAF;
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

    bsp_hvm->cpu_id = 0;
    for(i = 1; i < CPU_count; ++i){
      ap_hvm[i].cpu_id = i;
      ap_hvm[i].st = bsp_hvm->st;
      ap_hvm[i].vmxon_region = (uint64_t)bsp_hvm->vmxon_region + i * 4096;
      ap_hvm[i].vmcs = (uint64_t)bsp_hvm->vmcs + i * 4096;
      ap_hvm[i].host_stack = (uint64_t)bsp_hvm->host_stack + i * 65536;
    }

    if(!prepare_shared_hvm_tables(bsp_hvm)){
      print(L"Error preparing shared hvm tables.\r\n");
    }


    st = BS->OpenProtocol(image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if(EFI_ERROR(st)){
      print(L"Error getting a LoadedImageProtocol handle.\r\n");
      goto epilog;
    }
    printf("Image base: %x\r\n", loaded_image->ImageBase);

    //migrate_image(loaded_image);

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

    
    //print(L"HOST_CR3: "); print_uintx(get_cr3()); print(L"\r\n");

    // TEST SIPI TRAP
    //start_smp();

    /*uint8_t * eip = test;
    for(i = 0; i < 14; ++i){
      if(exec_instruction(NULL, &eip) == EMU_ERROR){
        printf("Emulator error.\r\n");
        break;
      }
    }*/

    vmcs_init(bsp_hvm);
    //print(L"GUEST_CR3: "); print_uintx(vmx_read(GUEST_CR3)); print(L"\r\n");
    bsp_printf("Press a key to start VM.\r\n");
    wait_for_key();
    bsp_printf("Starting VM...\r\n");
    vm_start();
    print(L"Hello from the Guest VM!\r\n");
    //print(L"GUEST_CR3: "); print_uintx(get_cr3()); print(L"\r\n");

    //vmx_enable_a20_line();

    epilog:
    //BS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_CALLBACK, callback, NULL, &evt);
    return st;
}
