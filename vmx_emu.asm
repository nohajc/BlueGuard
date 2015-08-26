global emu_rdmsr
global emu_wrmsr
global emu_cpuid

section .text

emu_rdmsr:
	mov r9,rdx
	rdmsr
	mov [r9],rdx
	mov [r8],rax
	ret

emu_wrmsr:
	mov rax,r8
	wrmsr
	ret

emu_cpuid:
	mov r10,rcx
	mov r11,rdx
	mov rax,[r10]
	cpuid
	mov [r10],rax
	mov [r11],rbx
	mov [r8],rcx
	mov [r9],rdx
	ret