#include <stdint.h>
#include <stdbool.h>
#include "realmode_emu.h"
#include "vmx_api.h"
#include "vm_setup.h"
#include "string.h"
#include "smp.h"

uint8_t test[] = {
	0xE9, 0x3D, 0x06,
	0xFA, 
	0x66, 0x2B, 0xC0,
	0x8C, 0xC8,
	0x8E, 0xD8,
	0x66, 0xC1, 0xE0, 0x04, // shl
	0x66, 0x8B, 0xF8,
	0x66, 0x67, 0x0F, 0x01, 0x15, 0x0C, 0x00, 0x00, 0x00, // lgdt
	0x0F, 0x20, 0xC0,
	0x66, 0x83, 0xC8, 0x11, // or
	0x0F, 0x22, 0xC0,
	0xB8, 0x20, 0x00,
	0x8E, 0xD8,
	0x66, 0x67, 0xFF, 0x6F, 0x60 // jmp dword far
};

/*

We emulate only the instructions used by the Windows AP trampoline code:
sub, mov, shl, lgdt, mov cr0, or, jmp dword far

PREF | OPCODE | ModR/M | SIB | Disp | Imm


ModR/M
7:6 mod | 5:3 reg/opcode | 2:0 R/M

SIB
7:6 Scale | 5:3 Index | 2:0 Base


• REX.W — Indicates the use of a REX prefix that affects operand size or instruction semantics. The ordering of
the REX prefix and other optional/mandatory instruction prefixes are discussed Chapter 2. Note that REX
prefixes that promote legacy instructions to 64-bit behavior are not listed explicitly in the opcode column.

• /digit — A digit between 0 and 7 indicates that the ModR/M byte of the instruction uses only the r/m (register
or memory) operand. The reg field contains the digit that provides an extension to the instruction's opcode.

• /r — Indicates that the ModR/M byte of the instruction contains a register operand and an r/m operand.

• cb, cw, cd, cp, co, ct — A 1-byte (cb), 2-byte (cw), 4-byte (cd), 6-byte (cp), 8-byte (co) or 10-byte (ct) value
following the opcode. This value is used to specify a code offset and possibly a new value for the code segment
register.

• ib, iw, id, io — A 1-byte (ib), 2-byte (iw), 4-byte (id) or 8-byte (io) immediate operand to the instruction that
follows the opcode, ModR/M bytes or scale-indexing bytes. The opcode determines if the operand is a signed
value. All words, doublewords and quadwords are given with the low-order byte first.

• +rb, +rw, +rd, +ro — Indicated the lower 3 bits of the opcode byte is used to encode the register operand
without a modR/M byte. The instruction lists the corresponding hexadecimal value of the opcode byte with low
3 bits as 000b. In non-64-bit mode, a register code, from 0 through 7, is added to the hexadecimal value of the
opcode byte. In 64-bit mode, indicates the four bit field of REX.b and opcode[2:0] field encodes the register
operand of the instruction. “+ro” is applicable only in 64-bit mode. See Table 3-1 for the codes.

• +i — A number used in floating-point instructions when one of the operands is ST(i) from the FPU register stack.
The number i (which can range from 0 to 7) is added to the hexadecimal byte given at the left of the plus sign
to form a single opcode byte.

*/

// instructions
enum{
	NOP, SUB, MOV, SHL, LGDT, OR, JMP, FARJMP, CLI, UNDEF, SHIFT, LOGICAL, DT, JUMP
};

char *instr_str[] = {
	"NOP", "SUB", "MOV", "SHL", "LGDT", "OR", "JMP", "JMP FAR", "CLI", "UNDEF", "SHIFT", "LOGICAL", "DT", "JUMP"
};

// arg types
enum{
	R16, R32, RM16, RM32, M16, M32, M16_16, M16_24, M16_32, SREG, CR, IMM8, IMM16, IMM32, OFF16, OFF32, NIL
};

// r16 encoding
char *r16_str[] = {
	"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"
};

// r32 encoding
char *r32_str[] = {
	"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
};

// sreg encoding
char *sreg_str[] = {
	"ES", "CS", "SS", "DS", "FS", "GS"
};

#define GOTO_NEXT(label) do { ++eip; goto label; } while(0)
#define GOTO_CURR(label) goto label
#define ARG(type) (prefix & PREF_O32) ? type##32 : type##16

#define PREF_O32 1
#define PREF_A32 2

#define IS_IMM(arg) (arg == IMM8 || arg == IMM16 || arg == IMM32)


int exec_instruction(GUEST_REGS * regs, uint8_t ** p_eip){
	//uint8_t * eip = (uint8_t*)vmx_read(GUEST_EIP);
	uint8_t * eip = *p_eip;
	uint32_t prefix = 0;
	uint32_t op = UNDEF;
	uint32_t arg[3]; // type
	uint8_t imm8_u;
	int8_t imm8_s;
	uint16_t imm16_u;
	int16_t imm16_s;
	uint32_t imm32_u;
	int32_t imm32_s;
	int16_t offset16;
	bool imm_signed = false;
	uint32_t reg[3];
	uint32_t base;
	uint64_t addr;
	uint8_t tmp, mod, rm, rm_op, r_op;

	decode_prefix:
	switch(*eip){
		case 0x66:
			prefix |= PREF_O32;
			GOTO_NEXT(decode_opcode);
		case 0x67:
			prefix |= PREF_A32;
			GOTO_NEXT(decode_opcode);
		// INCOMPLETE
		default:
			GOTO_CURR(decode_opcode);
	}

	decode_opcode:
	switch(*eip){
		case 0x2B: // 2B /r SUB r16, r/m16
			op = SUB;
			arg[1] = ARG(R);
			arg[2] = ARG(RM);
			r_op = 1; // RM
			rm_op = 2;
			GOTO_NEXT(decode_modrm);
		case 0x83:
			op = LOGICAL;
			arg[1] = ARG(RM);
			arg[2] = IMM8;
			rm_op = 1; // MI
			imm_signed = true;
			GOTO_NEXT(decode_modrm);
		case 0x8B:
			op = MOV;
			arg[1] = ARG(R);
			arg[2] = ARG(RM);
			r_op = 1; // RM
			rm_op = 2;
			GOTO_NEXT(decode_modrm);
		case 0x8C:
			op = MOV;
			arg[1] = ARG(R);
			arg[2] = SREG;
			r_op = 2; // MR
			rm_op = 1;
			GOTO_NEXT(decode_modrm);
		case 0x8E:
			op = MOV;
			arg[1] = SREG;
			arg[2] = ARG(R);
			r_op = 1; // RM
			rm_op = 2;
			GOTO_NEXT(decode_modrm);
		case 0xC1:
			op = SHIFT;
			arg[1] = ARG(RM);
			arg[2] = IMM8;
			rm_op = 1; // MI
			GOTO_NEXT(decode_modrm);
		case 0xE9:
			op = JMP;
			arg[1] = ARG(OFF);
			arg[2] = NIL;
			GOTO_NEXT(decode_offset);
		case 0xFA:
			op = CLI;
			arg[1] = arg[2] = NIL;
			GOTO_NEXT(emulate_instr);
		case 0xFF:
			op = JUMP;
			arg[1] = ARG(M16_);
			arg[2] = NIL;
			GOTO_NEXT(decode_modrm);
		// INCOMPLETE
		default:
			if((*eip & ~7) == 0xB8){
				op = MOV;
				arg[1] = ARG(R);
				arg[2] = ARG(IMM);
				reg[1] = *eip & 7;
				GOTO_NEXT(decode_imm);
			}
			else if(*eip == 0x0F){
				++eip;
				if(*eip == 0x01){
					op = DT;
					arg[1] = (prefix & PREF_O32) ? M16_32 : M16_24;
					arg[2] = NIL;
					GOTO_NEXT(decode_modrm);
				}
				else if(*eip == 0x20){
					op = MOV;
					arg[1] = R32;
					arg[2] = CR;
					r_op = 2; // MR
					rm_op = 1;
					GOTO_NEXT(decode_modrm);
				}
				else if(*eip == 0x22){
					op = MOV;
					arg[1] = CR;
					arg[2] = R32;
					r_op = 1; // RM
					rm_op = 2;
					GOTO_NEXT(decode_modrm);
				}
			}
			else{
				GOTO_CURR(decode_prefix);
			}
			// INCOMPLETE
			return EMU_ERROR;
	}

	decode_modrm:
	tmp = *eip;
	mod = (tmp >> 6) & 3;
	reg[0] = (tmp >> 3) & 7;
	rm = tmp & 7;

	//printf("DEBUG: mod = %x, reg = %x, rm = %x\r\n", mod, reg[0], rm);
	if(op == DT){
		if(reg[0] == 2){
			op = LGDT;
			if(prefix & PREF_A32){
				if(mod == 0 && rm == 5){
					base = -1;
					GOTO_NEXT(decode_addr32);
				}
			}
		}
		// INCOMPLETE
	}
	else if(op == JUMP){
		if(reg[0] == 5){
			op = FARJMP;
			if(arg[1] == M16_16 || M16_32){
				if(prefix & PREF_A32){
					if(mod == 1 && rm == 7){
						base = rm;
						GOTO_NEXT(decode_addr8);
					}
				}
			}
		}
		// INCOMPLETE
	}
	else if(op == SHIFT){ // reg field contains opcode extension
		if(reg[0] == 4){
			op = SHL;
		}
		// INCOMPLETE
	}
	else if(op == LOGICAL){
		if(reg[0] == 1){
			op = OR;
		}
		// INCOMPLETE
	}
	else{ // reg field does contain register
		reg[r_op] = reg[0];
	}

	if(arg[r_op] == CR || arg[r_op] == SREG){
		reg[rm_op] = rm;
		GOTO_NEXT(emulate_instr);
	}
	else if(mod == 3){
		arg[rm_op] = ARG(R);
		reg[rm_op] = rm;
		if(IS_IMM(arg[2])){
			GOTO_NEXT(decode_imm);
		}
		GOTO_NEXT(emulate_instr);
	} // INCOMPLETE


	decode_imm:
	if(arg[2] == IMM8){
		if(imm_signed){
			imm8_s = *(int8_t*)eip;
			++eip;
			GOTO_CURR(emulate_instr);
		}
		else{
			imm8_u = *(uint8_t*)eip;
			++eip;
			GOTO_CURR(emulate_instr);
		}
	}
	else if(arg[2] == IMM16){
		if(imm_signed){
			imm16_s = *(int16_t*)eip;
			eip += 2;
			GOTO_CURR(emulate_instr);
		}
		else{
			imm16_u = *(uint16_t*)eip;
			eip += 2;
			GOTO_CURR(emulate_instr);
		}
	}
	else if(arg[2] == IMM32){
		if(imm_signed){
			imm32_s = *(int32_t*)eip;
			eip += 4;
			GOTO_CURR(emulate_instr);
		}
		else{
			imm32_u = *(uint32_t*)eip;
			eip += 4;
			GOTO_CURR(emulate_instr);
		}
	}

	decode_addr32:
	addr = *(uint32_t*)eip;
	eip += 4;
	GOTO_CURR(emulate_instr);

	decode_addr8:
	addr = *(uint8_t*)eip;
	++eip;
	GOTO_CURR(emulate_instr);


	decode_offset:
	if(arg[1] == OFF16){
		offset16 = *(int16_t*)eip;
		eip += 2;
		GOTO_CURR(emulate_instr);
	}
	// INCOMPLETE

	return EMU_ERROR;

	emulate_instr:

	if(op == SUB){
		if(arg[1] == R32 && arg[2] == R32){
			((uint64_t*)regs)[reg[1]] = ((uint64_t*)regs)[reg[1]] - ((uint64_t*)regs)[reg[2]];
		}
		// INCOMPLETE
	}
	else if(op == MOV){
		if(arg[1] == R32 && arg[2] == R32){
			((uint64_t*)regs)[reg[1]] = ((uint64_t*)regs)[reg[2]];
		}
		else if(arg[1] == R16 && arg[2] == R16){
			((uint64_t*)regs)[reg[1]] = ((uint64_t*)regs)[reg[2]];
		}
		else if(arg[1] == R16 && arg[2] == SREG){
			((uint64_t*)regs)[reg[1]] = vmx_read(GUEST_ES_SELECTOR + (reg[2] << 1));
		}
		else if(arg[1] == SREG && arg[2] == R16){
			vmx_write(GUEST_ES_SELECTOR + (reg[1] << 1), ((uint64_t*)regs)[reg[2]]);
			if(!regs->hvm->guest_realmode){
				set_guest_selector(vmx_read(GUEST_GDTR_BASE), reg[1], ((uint64_t*)regs)[reg[2]]);
			}
		}
		else if(arg[1] == R16 && arg[2] == IMM16){
			if(!imm_signed){
				((uint64_t*)regs)[reg[1]] = imm16_u;
			}
		}
		else if(arg[1] == R32 && arg[2] == CR){
			if(reg[1] == 0){
				((uint64_t*)regs)[reg[1]] = regs->hvm->guest_CR0;
			}
		}
		else if(arg[1] == CR && arg[2] == R32){
			if(reg[1] == 0){
				regs->hvm->guest_CR0 = ((uint64_t*)regs)[reg[2]];
				vmx_write(GUEST_CR0, regs->hvm->guest_CR0 | X86_CR0_PE | X86_CR0_PG | X86_CR0_NE);

				if(regs->hvm->guest_CR0 & X86_CR0_PE){
					regs->hvm->guest_realmode = false;
				}
			}
			// INCOMPLETE
		}
	}
	else if(op == SHL){
		if(arg[1] == R32 && arg[2] == IMM8){
			((uint64_t*)regs)[reg[1]] <<= imm8_u;
		}
		// INCOMPLETE
	}
	else if(op == OR){
		if(arg[1] == R32 && arg[2] == IMM8){
			if(imm_signed){
				((uint64_t*)regs)[reg[1]] = ((uint64_t*)regs)[reg[1]] | (int32_t)imm8_s;
			}
		}
		// INCOMPLETE
	}
	else if(op == JMP){
		if(arg[1] == OFF16){
			eip += offset16;
		}
		// INCOMPLETE
	}
	else if(op == LGDT){
		if(arg[1] == M16_32){
			if(base == -1){
				void * lin_addr;
				if(regs->hvm->guest_realmode){
					lin_addr = (void*)((vmx_read(GUEST_DS_SELECTOR) << 4) + addr);
				}
				else{
					lin_addr = (void*)addr;
				}
				vmx_write(GUEST_GDTR_LIMIT, *(uint16_t*)lin_addr);
				vmx_write(GUEST_GDTR_BASE, *(uint32_t*)(lin_addr + 2));
			}
		}
		// INCOMPLETE
	}
	else if(op == FARJMP){
		if(arg[1] == M16_32){
			if(base != -1){
				if(!regs->hvm->guest_realmode){
					void * lin_addr = (void*)((uint64_t*)regs)[base] + addr; // Assuming flat ds segment!
					if(prefix & PREF_O32){
						uint16_t far_seg = *(uint16_t*)((uint64_t)lin_addr + 4);
						vmx_write(GUEST_CS_SELECTOR, far_seg);
						set_guest_selector(vmx_read(GUEST_GDTR_BASE), CS, far_seg);

						uint64_t tmp = *(uint32_t*)lin_addr;
						eip = (uint8_t*)tmp;
						emulate_farjmp:
						regs->hvm->guest_realsegment = false;
					}
				}
			}
		}
		// INCOMPLETE
	}

	*p_eip = eip;
	return EMU_SUCCESS;

	if((op == LGDT) && (prefix & PREF_O32)){
		printf("O32 ");
	}

	printf("%s ", instr_str[op]);

	if((op == FARJMP) && (prefix & PREF_A32)){
		printf("dword ");
	}

	switch(arg[1]){
		case R16:
			printf("%s,", r16_str[reg[1]]);
			break;
		case R32:
			printf("%s,", r32_str[reg[1]]);
			break;
		case SREG:
			printf("%s,", sreg_str[reg[1]]);
			break;
		case CR:
			printf("CR%u,", reg[1]);
			break;
		case M16_24:
		case M16_32:
			if(base == -1){
				if(prefix & PREF_A32){
					printf("[dword ");
				}
				else{
					printf("[word ");
				}
			}
			else{
				if(prefix & PREF_O32){
					printf("[%s+", r32_str[base]);
				}
				else{
					printf("[%s+", r16_str[base]);
				}
			}
			printf("0x%x]", addr);
			break;
		case OFF16:
			printf("0x%x", (uint64_t)(eip - test + offset16));
			break;
		case NIL:
			break;
		// INCOMPLETE
		default:
			return EMU_ERROR;
	}

	switch(arg[2]){
		case R16:
			printf("%s", r16_str[reg[2]]);
			break;
		case R32:
			printf("%s", r32_str[reg[2]]);
			break;
		case SREG:
			printf("%s", sreg_str[reg[2]]);
			break;
		case CR:
			printf("CR%u", reg[2]);
			break;
		// INCOMPLETE
		case IMM8:
			if(imm_signed){
				printf("signed byte 0x%x", imm8_s);
			}
			else{
				printf("byte 0x%x", imm8_u);
			}
			break;
		case IMM16:
			if(imm_signed){
				printf("signed word 0x%x", imm16_s);
			}
			else{
				printf("word 0x%x", imm16_u);
			}
			break;
		case IMM32:
			if(imm_signed){
				printf("signed dword 0x%x", imm32_s);
			}
			else{
				printf("dword 0x%x", imm32_u);
			}
			break;
		case NIL:
			break;
		default:
			return EMU_ERROR;
	}
	printf("\r\n");

	*p_eip = eip;
	return EMU_SUCCESS;
}