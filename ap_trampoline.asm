extern ap_entry64
extern LAPIC_addr
extern ap_stacks
global init_tramp
global ap_tramp32
global ap_tramp64
global gdt32
global GDTR32
global GDT32_LABEL
global tramp_size
global JMP_START_PTR
global AP_START_LABEL
global AP_GDTR
global AP_IDTR
global AP_CR3
global AP_CR4
global JMP_32_PTR
global AP_32_LABEL
global JMP_64_PTR
global AP_64_LABEL
global ACTIVE_CPU_CNT


section .text

USE16

init_tramp:
	push cs
	pop ds ; We have data in the code segment

; Enable the A20 gate
set_A20_ap:
	in al, 0x64
	test al, 0x02
	jnz set_A20_ap
	mov al, 0xD1
	out 0x64, al
check_A20_ap:
	in al, 0x64
	test al, 0x02
	jnz check_A20_ap
	mov al, 0xDF
	out 0x60, al

	call ip0
ip0:
	pop bx ; Get IP
	mov bp,[bx+ACTIVE_CPU_CNT-ip0] ; save CPU number
	lock inc dword [bx+ACTIVE_CPU_CNT-ip0] ; Increase active CPU counter
	db 0xEA ; jmp 0:start
JMP_START_PTR:
	dw 0 ; offset
	dw 0 ; segment
start:
	call ip1
ip1:
	pop bx
	push cs
	pop ds
	lgdt [bx+GDTR32-ip1]
	mov eax,cr0
	or al,1
	mov cr0,eax
	db 0x66 ; jmp dword 8:ap_tramp32
	db 0xEA
JMP_32_PTR:
	dd 0
	dw 8

;align 16

USE32

ap_tramp32:
	mov eax,16
	mov ds,ax
	mov es,ax
	mov fs,ax
	mov gs,ax
	mov ss,ax
	;mov eax,100000b ; Set the PAE bit
	;mov cr4,eax
	mov esi,[bx+AP_CR4-ip1] ; Set PAE bit etc. according to the BSP's CR4
	mov cr4,esi
	mov esi,[bx+AP_CR3-ip1] ; Is PML4T really bellow 4 GB?
	mov cr3,esi
	mov ecx,0xC0000080 ; Read from the EFER MSR
	rdmsr
	or eax,0x00000100 ; Set the LME bit
	wrmsr
	mov eax,cr0
	or eax,0x80000000 ; Enable paging
	mov cr0,eax
	lgdt [bx+AP_GDTR-ip1]
	lidt [bx+AP_IDTR-ip1]
	db 0xEA ; Jump to 64bit segment (ap_tramp64)
JMP_64_PTR:
	dd 0   ; WE ASSUME THAT THE EFI IMAGE IS LOADED SOMEWHERE BELOW 4 GB
	dw 0   ; TODO: MAKE SURE IT IS BELOW 4 GB BY RELOCATING THE CODE IF NECESSARY!

;align 16

USE64

ap_tramp64:
	xor rax,rax
	mov ds,ax
	mov es,ax
	mov ss,ax
	mov fs,ax
	mov gs,ax
	; SETUP STACK
	mov ebx,ebp   ; get CPU number (n-th activated)
	and ebx,0xFF
	mov rcx,rbx
	shl rbx,12
	add rbx,[ap_stacks]
	mov rsp,rbx ; set stack location
	sti ; Enable interrupts
	call ap_entry64
sleep:
	hlt
	jmp sleep


; Taken from the Pure64 bootloader by ReturnInfinity

GDTR32:					; Global Descriptors Table Register
dw gdt32_end - gdt32 - 1		; limit of GDT (size minus one)
dq gdt32				; linear address of GDT

align 16
gdt32:
dw 0x0000, 0x0000, 0x0000, 0x0000	; Null desciptor
dw 0xFFFF, 0x0000
db 0x00, 0x9A, 0xCF, 0x00	; 32-bit code descriptor
dw 0xFFFF, 0x0000
db 0x00, 0x92, 0xCF, 0x00	; 32-bit data descriptor
gdt32_end:


GDT32_LABEL:
	dq gdt32

AP_32_LABEL:
	dq ap_tramp32

AP_64_LABEL:
	dq ap_tramp64

AP_START_LABEL:
	dq start

align 16
AP_GDTR:
	dw 0
	dq 0

AP_IDTR:
	dw 0
	dq 0

AP_CR3:
	dd 0

AP_CR4:
	dd 0

ACTIVE_CPU_CNT:
	dd 4

tramp_size:
	dd $ - $$
