#include <efi.h>
#include <efilib.h>
#include <stdarg.h>
#include "smp.h"
#include "regs.h"
#include "lib_uefi.h"
#include "ap_trampoline.h"
#include "spinlock.h"
#include "string.h"
#include "vm_setup.h"

int CPU_count = 0;
volatile int * CPUs_activated;
volatile int CPU_notified;
uint64_t LAPIC_addr;
uint8_t ProcAPIC_IDs[256];

void * ap_stacks;

EFI_GUID Acpi20TableGuid = ACPI_20_TABLE_GUID;

int verify_checksum(void * table, int len){
	int i;
	uint8_t chksum = 0;
	uint8_t * table_bytes = table;

	for(i = 0; i < len; ++i){
		chksum += table_bytes[i];
	}
	if(chksum != 0){
		print(L"Checksum error.\r\n");
		return 0;
	}

	return 1;
}

int read_apic_table(MADT * madt){
	uint8_t * apic_struct_ptr = (uint8_t*)&madt->APICStructs[0];
	uint8_t * apic_struct_end = (uint8_t*)((uint64_t)madt + madt->h.Length);

	LAPIC_addr = madt->LocalControllerAddress;
	print(L"LAPIC is at 0x"); print_uintx(LAPIC_addr); print(L"\r\n");

	while(apic_struct_ptr < apic_struct_end){
		APICStructHeader * hdr = (APICStructHeader*)apic_struct_ptr;
		if(hdr->Type == TypeProcLocalAPIC){
			EntryProcLocalAPIC * lapic = (EntryProcLocalAPIC*)hdr;

			if(lapic->Flags & PROC_ENABLED){
				print(L"Detected CPU "); print_uint(lapic->ProcID); print(L" with APIC ID "); print_uint(lapic->APIC_ID); print(L"\r\n");
				ProcAPIC_IDs[CPU_count++] = lapic->APIC_ID;
			}
		}

		apic_struct_ptr += hdr->Length;
	}

	return 1;
}

int read_acpi2_tables(RSDP * rsdp){
	XSDT * xsdt;
	int sdt_ptr_count, i;
	CHAR16 signature[16] = {0};

	if(!strncmp("RSD PTR ", rsdp->Signature, sizeof(rsdp->Signature))){
		print(L"Located RSDP descriptor!\r\n");
		// Verify checksum
		if(!verify_checksum(rsdp, 20)){
			return 0;
		}
	}

	xsdt = (XSDT*)rsdp->XsdtAddress;
	if(!verify_checksum(xsdt, xsdt->h.Length)){
		return 0;
	}
	str2wstr(signature, xsdt->h.Signature, 4);
	print(signature); print(L"\r\n");

	sdt_ptr_count = (xsdt->h.Length - sizeof(xsdt->h)) / 8;
	for(i = 0; i < sdt_ptr_count; ++i){
		SDTHeader * sdt_hdr = (SDTHeader*)xsdt->PointerToOtherSDT[i];
		//print_uintx((uint64_t)sdt_hdr); print(L"\r\n");
		
		//str2wstr(signature, sdt_hdr->Signature, 4);
		//print(signature); print(L"\r\n");
		if(!strncmp(sdt_hdr->Signature, "APIC", 4)){
			MADT * madt = (MADT*)sdt_hdr;
			if(!verify_checksum(madt, madt->h.Length)){
				return 0;
			}
			read_apic_table((MADT*)madt);
		}
	}

	return 1;
}


int guid_eq(EFI_GUID a, EFI_GUID b){
	int i;
	if(a.Data1 != b.Data1) return 0;
	if(a.Data2 != b.Data2) return 0;
	if(a.Data3 != b.Data3) return 0;

	for(i = 0; i < 4; ++i){
		if(a.Data4[i] != b.Data4[i]) return 0;
	}

	return 1;
}

inline uint32_t read_lapic_reg(uint32_t offset){
	return *(uint32_t*)(LAPIC_addr + offset);
}

inline void write_lapic_reg(uint32_t offset, uint32_t value){
	*(uint32_t*)(LAPIC_addr + offset) = value;
}

int activate_APs(uint64_t tramp_addr){
	uint8_t bspLAPIC_ID = (uint8_t)read_lapic_reg(LAPIC_ID_REG);
	int i;
	uint8_t tmp;
	//uint32_t * ap_cr0 = (uint32_t*)(tramp_addr + tramp_size - 4);

	print(L"Press a key to activate APs...\r\n");

	wait_for_key();

	//print(L"BSP LAPIC ID: "); print_uint(bspLAPIC_ID); print(L"\r\n");

	for(i = 0; i < CPU_count; ++i){
		if(ProcAPIC_IDs[i] == bspLAPIC_ID) continue; // We won't be sending IPIs to ourselves
		//CPU_notified = 0;

		tmp = *CPUs_activated;

		// Send INIT
		write_lapic_reg(INT_COMMAND_REG_HIGH, (uint32_t)ProcAPIC_IDs[i] << 24); // Set destination
		write_lapic_reg(INT_COMMAND_REG_LOW, DM_INIT | LVL_ASSERT); // Set interrupt type

		//print(L"INIT send to CPU "); print_uint(i); print(L"\r\n");
		while(read_lapic_reg(INT_COMMAND_REG_LOW) & DLV_STATUS); // Wait for completion

		BS->Stall(10 * 1000); // Wait 10 ms

		// Send SIPI
		write_lapic_reg(INT_COMMAND_REG_HIGH, (uint32_t)ProcAPIC_IDs[i] << 24); // Set destination
		// Entry point must be a 4 KB aligned address below 1 MB. It is coded as 8-bit vector with a value of entry_addr >> 12.
		write_lapic_reg(INT_COMMAND_REG_LOW, DM_STARTUP | LVL_ASSERT | (tramp_addr >> 12)); // Set interrupt type and entry point

		//print(L"SIPI send to CPU "); print_uint(i); print(L"\r\n");
		while(read_lapic_reg(INT_COMMAND_REG_LOW) & DLV_STATUS); // Wait for completion

		//BS->Stall(1 * 1000); // Wait 1 ms
		while(*CPUs_activated == tmp);
	}
	// TODO: Add better synchronization (continue flag)
	BS->Stall(50 * 1000); // Wait 50 ms


	print(L"Active CPU count: "); print_uint(*CPUs_activated); print(L"\r\n");

	return 1;
}

int init_smp(void){
	EFI_CONFIGURATION_TABLE * CT = ST->ConfigurationTable;
	int i;
	int acpi1_idx = -1;
	int acpi2_idx = -1;

	for(i = 0; i < ST->NumberOfTableEntries; ++i){
		if(guid_eq(CT[i].VendorGuid, Acpi20TableGuid)){
			acpi2_idx = i;
			//break;
		}
		else if(guid_eq(CT[i].VendorGuid, AcpiTableGuid)){
			acpi1_idx = i;
		}
	}

	if(acpi2_idx >= 0){
		print(L"Found ACPI 2 GUID\r\n");
		read_acpi2_tables((RSDP*)CT[acpi2_idx].VendorTable);
	}
	else if(acpi1_idx >= 0){
		print(L"Found ACPI 1 GUID\r\n");
		// ACPI 1 Support not implemented
	}

	return 1;
}

int start_smp(void){
	EFI_PHYSICAL_ADDRESS ap_init_code = 0xFFFF;
	EFI_STATUS st;
	uint64_t apic_base_msr = get_msr(MSR_IA32_APIC_BASE);

	if(!(apic_base_msr & APIC_ENABLED)){
		// TODO enable APIC manually
		return 0;
	}
	//print(L"Local APIC is enabled!\r\n");

	st = BS->AllocatePages(AllocateMaxAddress, EfiLoaderCode, 1, &ap_init_code);
	if(st != EFI_SUCCESS){
		print(L"Error allocating page within the 64 kB limit.\r\n");
		return 0;
	}
	print(L"Allocated page for AP init code at 0x"); print_uintx((uint64_t)ap_init_code); print(L"\r\n");

	// Init trampoline code globals
	get_gdt_base_limit(&AP_GDTR.base, &AP_GDTR.limit);
	get_idt_base_limit(&AP_IDTR.base, &AP_IDTR.limit);
	AP_CR3 = get_cr3();
	AP_CR4 = get_cr4();	

	uint16_t start_label_offset = AP_START_LABEL - (uint64_t)init_tramp;
	JMP_START_PTR.seg = 0;
	JMP_START_PTR.addr = (uint16_t)ap_init_code + start_label_offset;

	uint16_t acpu_cnt_offset = (uint64_t)&ACTIVE_CPU_CNT - (uint64_t)init_tramp;
	CPUs_activated = (int*)((uint64_t)ap_init_code + acpu_cnt_offset);

	uint16_t gdt32_offset = GDT32_LABEL - (uint64_t)init_tramp;
	GDTR32.base = (uint64_t)ap_init_code + gdt32_offset;

	uint16_t tramp32_offset = AP_32_LABEL - (uint64_t)init_tramp;
	JMP_32_PTR.addr = (uint32_t)ap_init_code + tramp32_offset;

	//uint16_t tramp64_offset = AP_64_LABEL - (uint64_t)init_tramp;
	//JMP_64_PTR.addr = (uint32_t)ap_init_code + tramp64_offset;
	JMP_64_PTR.seg = get_cs();
	JMP_64_PTR.addr = (uint64_t)ap_tramp64;
	
	//print(L"JMP_64_PTR: "); print_uintx(JMP_64_PTR.addr); print(L"\r\n");

	/*BS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, CPU_count, (EFI_PHYSICAL_ADDRESS*)&ap_stacks);
	for(i = 1; i < CPU_count; ++i){
		ap_hvm[i].ap_guest_stack = ((uint64_t)ap_stacks + i * 4096);
	}*/

	// Copy the trampoline code in place
	CopyMem((void*)ap_init_code, (void*)init_tramp, tramp_size);

	/*print(L"OPCODE: ");
	for(i = tramp32_offset - 8; i < tramp32_offset; ++i){
		print_uintx(((uint8_t*)ap_init_code)[i]); print(L" ");
	} print(L"\r\n");*/


	*CPUs_activated = 1;
	activate_APs((uint64_t)ap_init_code);

	char str[128];
	int msg_sources = CPU_count - 1;
	while(msg_sources){
		recv_msg(str);
		if(!strcmp(str, "MSG_END")){
			--msg_sources;
		}
		else{
			printf("%s", str);
		}
	}

	BS->FreePages(ap_init_code, 1);
	return 1;
}

lock_t wait_for_send = 1;
lock_t wait_for_recv = 0;

char msg_buffer[128];

void recv_msg(char * str){
	acquire_lock(&wait_for_send);
	
	CopyMem(str, msg_buffer, strlen(msg_buffer) + 1);

	release_lock(&wait_for_recv);
}

void send_msg(char * str){
	acquire_lock(&wait_for_recv);

	CopyMem(msg_buffer, str, strlen(str) + 1);

	release_lock(&wait_for_send);
}

int bsp_printf(const char * format, ...){
	int ret;
	char str[256];
	va_list params;
	va_start(params, format);
	
	ret = vsprintf(str, format, params);

	uint64_t apic_base_msr = get_msr(MSR_IA32_APIC_BASE);
	if(apic_base_msr & IS_BSP){
		printf("%s", str);
	}
	else{
		send_msg(str);
	}

	va_end(params);
	return ret;
}

void ap_entry64(uint8_t cpu){
	uint32_t vmx_rev, struct_size;
	uint64_t apic_base_msr = get_msr(MSR_IA32_APIC_BASE);
	bsp_printf("%u: MSR_IA32_APIC_BASE: %x\r\n", cpu, apic_base_msr);

	/*bsp_printf("%u: VMXON-region = %x\r\n", cpu, ap_hvm[cpu].vmxon_region);
	bsp_printf("%u: VMCS = %x\r\n", cpu, ap_hvm[cpu].vmcs);
	bsp_printf("%u: Host stack = %x\r\n", cpu, ap_hvm[cpu].host_stack);
	bsp_printf("%u: GDT base = %x\r\n", cpu, ap_hvm[cpu].st->gdt_base);*/

	if(vmx_supported()){
        bsp_printf("%u: VMX is supported!\r\n", cpu);
    }
    else{
        bsp_printf("%u: Error: VMX is not supported.\r\n", cpu);
        goto msg_end;
    }

    vmx_get_revision_and_struct_size(&vmx_rev, &struct_size);

    bsp_printf("%u: VMX revision: %u\r\n", cpu, vmx_rev);
    bsp_printf("%u: Struct size: %u\r\n", cpu, struct_size);

    // Write revision ID at the start of VMXON-region
    *(uint32_t*)ap_hvm[cpu].vmxon_region = vmx_rev;
    vmx_enable(); // Set bit 13 of CR4 to 1 to enable the VMX operations

    if(vmx_switch_to_root_op((void*)ap_hvm[cpu].vmxon_region)){
      bsp_printf("%u: Switched to VMX-root-operation mode!\r\n", cpu);
    }
    else{
      bsp_printf("%u: Error switching to VMX-root-operation mode.\r\n", cpu);
      goto msg_end;
    }

    *(uint32_t*)ap_hvm[cpu].vmcs = vmx_rev;
    if(vmx_vmcs_activate((void*)ap_hvm[cpu].vmcs)){
      bsp_printf("%u: Activated VMCS!\r\n", cpu);
    }
    else{
      bsp_printf("%u: Error activating VMCS.\r\n", cpu);
      goto msg_end;
    }

    bsp_printf("%u: Debug area: %x\r\n", cpu, ap_hvm[cpu].st->debug_area);

    vmcs_init(&ap_hvm[cpu]);
    ap_hvm[cpu].guest_CR0 &= ~X86_CR0_PE;
    ap_hvm[cpu].guest_CR4 &= ~X86_CR4_PAE;
    if(features.pse){
    	ap_hvm[cpu].guest_CR4 |= X86_CR4_PSE;
    }
    ap_hvm[cpu].guest_realmode = true;
    ap_hvm[cpu].guest_realsegment = true;
    
    vmx_write(GUEST_CR3, ap_hvm[cpu].st->host_cr3);
    /*vmx_write(GUEST_ES_SELECTOR, 0);
	vmx_write(GUEST_CS_SELECTOR, 0);
	vmx_write(GUEST_SS_SELECTOR, 0);
	vmx_write(GUEST_DS_SELECTOR, 0);
	vmx_write(GUEST_FS_SELECTOR, 0);
	vmx_write(GUEST_GS_SELECTOR, 0);
	vmx_write(GUEST_ES_BASE, 0);
	vmx_write(GUEST_CS_BASE, 0);
	vmx_write(GUEST_SS_BASE, 0);
	vmx_write(GUEST_DS_BASE, 0);
	vmx_write(GUEST_FS_BASE, 0);
	vmx_write(GUEST_GS_BASE, 0);
	vmx_write(GUEST_ES_LIMIT, 0xFFFF);
	vmx_write(GUEST_CS_LIMIT, 0xFFFF);
	vmx_write(GUEST_SS_LIMIT, 0xFFFF);
	vmx_write(GUEST_DS_LIMIT, 0xFFFF);
	vmx_write(GUEST_FS_LIMIT, 0xFFFF);
	vmx_write(GUEST_GS_LIMIT, 0xFFFF);
	vmx_write(GUEST_ES_AR_BYTES, 0xF3);
	vmx_write(GUEST_CS_AR_BYTES, 0xF3);
	vmx_write(GUEST_SS_AR_BYTES, 0xF3);
	vmx_write(GUEST_DS_AR_BYTES, 0xF3);
	vmx_write(GUEST_FS_AR_BYTES, 0xF3);
	vmx_write(GUEST_GS_AR_BYTES, 0xF3);
	vmx_write(GUEST_EFLAGS, EFLAGS_IOPL3 | EFLAGS_VM);
	vmx_write(VM_ENTRY_CONTROLS, init_control_field(0, MSR_IA32_VMX_ENTRY_CTLS));*/

    vmx_write(GUEST_ACTIVITY_STATE, STATE_WAIT_FOR_SIPI);

    send_msg("MSG_END");
    vm_start();
	/*uint64_t error_code;

	vmx_write(GUEST_ESP, 0xFFFF);
	vmx_write(GUEST_EIP, 0xF000);

	vmx_launch();

	error_code = vmx_read(VM_INSTRUCTION_ERROR);
	bsp_printf("VMLAUNCH failed.\r\nError code: %u\r\n", error_code);*/

	msg_end:
	send_msg("MSG_END");
}