#include "reloc_pe.h"
#include "lib_uefi.h"

int64_t reloc_image(IMAGE_DOS_HEADER * img, uint64_t new_base){
	IMAGE_NT_HEADERS64 * nt_headers64 = (IMAGE_NT_HEADERS64*)((uint64_t)img + img->e_lfanew);
	IMAGE_BASE_RELOCATION * base_reloc = (IMAGE_BASE_RELOCATION*)((uint64_t)img + nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	void * base_reloc_end = (void*)((uint64_t)base_reloc + nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	int i;

	int64_t delta = new_base - (int64_t)img;

	//print(L"PE RELOCATIONS:\r\n");
	while(base_reloc != base_reloc_end){
		int items = (base_reloc->SizeOfBlock - 8) / 2;
		uint64_t block_base = base_reloc->VirtualAddress;

		for(i = 0; i < items; ++i){
			uint8_t type = base_reloc->TypeOffset[i] >> 12;
			uint64_t offset = block_base + (base_reloc->TypeOffset[i] & 0xFFF);
			/*if(type == IMAGE_REL_BASED_ABSOLUTE){
				print(L"ABSOL ");
			}
			else if(type == IMAGE_REL_BASED_DIR64){
				print(L"DIR64 ");
			}

			print_uintx(offset); print(L"	");*/
			if(type == IMAGE_REL_BASED_DIR64){
				*(int64_t*)(new_base + offset) += delta;
			}
		}
		base_reloc = (IMAGE_BASE_RELOCATION*)((uint64_t)base_reloc + base_reloc->SizeOfBlock);
	}
	//print(L"Size of image [PE]: "); print_uint(nt_headers64->OptionalHeader.SizeOfImage); print(L"\r\n");

	return 1;
}