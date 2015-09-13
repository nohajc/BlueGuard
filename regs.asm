global get_rbp
global get_rsp
global get_cs
global get_ds
global get_es
global get_fs
global get_gs
global get_ss
global get_tr
global get_cr0
global get_cr3
global get_cr4
global get_dr7
global get_rflags
global get_gdt_base_limit
global get_idt_base_limit
global get_ldtr
global get_msr
global set_msr
global set_tr
global set_gdt_base_limit

section .text

get_rbp:
	mov rax,rbp
	ret

get_rsp:
	mov rax,rsp
	ret

get_cs:
	mov rax,cs
	ret

get_ds:
	mov rax,ds
	ret

get_es:
	mov rax,es
	ret

get_fs:
	mov rax,fs
	ret

get_gs:
	mov rax,gs
	ret

get_ss:
	mov rax,ss
	ret

get_tr:
	str rax
	ret

get_cr0:
	mov rax,cr0
	ret

get_cr3:
	mov rax,cr3
	ret

get_cr4:
	mov rax,cr4
	ret

get_dr7:
	mov rax,dr7
	ret

get_rflags:
	pushf
	pop rax
	ret

get_gdt_base_limit:
	sub rsp,10
	sgdt [rsp]
	mov rax,[rsp+2]
	mov [rcx],rax
	mov ax,[rsp]
	mov [rdx],ax
	add rsp,10
	ret

get_idt_base_limit:
	sub rsp,10
	sidt [rsp]
	mov rax,[rsp+2]
	mov [rcx],rax
	mov ax,[rsp]
	mov [rdx],ax
	add rsp,10
	ret

get_ldtr:
	sldt rax
	ret

get_msr:
	rdmsr
	shl rdx,32
	or rax,rdx
	ret

set_msr:
	mov rax,rdx
	and rax,0FFFFFFFFh
	shr rdx,32
	wrmsr
	ret

set_tr:
	push rcx
	cli
	ltr [rsp]
	sti
	pop rcx
	ret

set_gdt_base_limit:
	sub rsp,10
	mov [rsp],dx
	mov [rsp+2],rcx
	cli
	lgdt [rsp]
	sti
	add rsp,10
	ret
