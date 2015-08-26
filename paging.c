#include <stdint.h>

#define PG_PRESENT 1
#define PG_SIZE 1<<7

uint64_t copy_pt(uint64_t pt){
	int i;
	uint64_t * pt_entry = (uint64_t*)pdt;
	uint64_t * copied_pt_entry = malloc(512 * 8);

	memcpy(copied_pt_entry, pt_entry, 512 * 8);
	return (uint64_t)copied_pt_entry;
}

uint64_t copy_pdt(uint64_t pdt){
	int i;
	uint64_t * pdt_entry = (uint64_t*)pdt;
	uint64_t * copied_pdt_entry = malloc(512 * 8);
	uint64_t addr, copied_addr;

	for(i = 0; i < 512; ++i){
		if((pdt_entry[i] & PG_PRESENT) && !(pdt_entry[i] & PG_SIZE)){
			addr = pdt_entry[i] & ~0xFFF;
			copied_addr = copy_pt(addr);
			copied_pdt_entry[i] = copied_addr | (pdt_entry[i] & 0xFFF);
		}
		else{
			copied_pdt_entry[i] = pdt_entry[i];
		}
	}

	return (uint64_t)copied_pdt_entry;
}

uint64_t copy_pdpt(uint64_t pdpt){
	int i;
	uint64_t * pdpt_entry = (uint64_t*)pdpt;
	uint64_t * copied_pdpt_entry = malloc(512 * 8);
	uint64_t addr, copied_addr;

	for(i = 0; i < 512; ++i){
		if((pdpt_entry[i] & PG_PRESENT) && !(pdpt_entry[i] & PG_SIZE)){
			addr = pdpt_entry[i] & ~0xFFF;
			copied_addr = copy_pdt(addr);
			copied_pdpt_entry[i] = copied_addr | (pdpt_entry[i] & 0xFFF);
		}
		else{
			copied_pdpt_entry[i] = pdpt_entry[i];
		}
	}

	return (uint64_t)copied_pdpt_entry;
}

uint64_t copy_page_tables(uint64_t pml4t){
	int i;
	uint64_t * pml4t_entry = (uint64_t*)pml4t;
	uint64_t * copied_pml4t_entry = malloc(512 * 8);
	uint64_t addr, copied_addr;

	for(i = 0; i < 512; ++i){
		if(pml4t_entry[i] & PG_PRESENT){
			addr = pml4t_entry[i] & ~0xFFF;
			copied_addr = copy_pdpt(addr);
			copied_pml4t_entry[i] = copied_addr | (pml4t_entry[i] & 0xFFF);
		}
		else{
			copied_pml4t_entry[i] = pml4t_entry[i];
		}
	}

	return (uint64_t)copied_pml4t_entry;
}