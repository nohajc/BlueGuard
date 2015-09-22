extern vmexit_handler

global vmx_supported
global vmx_ug_supported
global vmx_ept_supported
global vmx_vpid_supported
global vmx_get_revision_and_struct_size
global vmx_enable
global vmx_switch_to_root_op
global vmx_vmcs_activate
global vmx_read
global vmx_write
global vmx_launch
global vmx_exit
global vmx_ret
global vmx_enable_a20_line
global vmx_disable_a20_line

section .text

vmx_supported:
	mov eax,1
	cpuid
	xor rax,rax
	bt ecx,5
	jnc vmx_s_end
	inc eax
vmx_s_end:
	ret

vmx_ug_supported:
	mov ecx,48bh ; IA32_VMX_PROCBASED_CTLS2
	mov r8,7 ; Unrestricted guest
	jmp vmx_check_capability_msr

vmx_ept_supported:
	mov ecx,48bh ; IA32_VMX_PROCBASED_CTLS2
	mov r8,1
	jmp vmx_check_capability_msr

vmx_vpid_supported:
	mov ecx,48bh ; IA32_VMX_PROCBASED_CTLS2
	mov r8,5
	jmp vmx_check_capability_msr

vmx_check_capability_msr:
	rdmsr
	xor rax,rax
	bt rdx,r8
	jnc vmx_chk_cap_end
	inc eax
vmx_chk_cap_end:
	ret
	

vmx_get_revision_and_struct_size:
	push rdx
	push rcx
	mov ecx,480h
	rdmsr
	pop rcx
	mov [rcx],eax
	pop rcx
	and edx,0fffh
	mov [rcx],edx
	ret

vmx_enable:
	mov rax,cr4
	bts rax,13
	mov cr4,rax
	mov rax,cr0
	bts rax,5
	mov cr0,rax
	ret

vmx_switch_to_root_op:
	xor rax,rax
	push rcx
	vmxon [rsp]
	jc vmx_stro_end
	inc eax
vmx_stro_end:
	pop rcx
	ret

vmx_vmcs_activate:
	xor rax,rax
	push rcx
	vmclear [rsp]
	jc vmx_va_end
	vmptrld [rsp]
	jc vmx_va_end
	inc eax
vmx_va_end:
	pop rcx
	ret

vmx_read:
	vmread rax,rcx
	ret

vmx_write:
	vmwrite rcx,rdx
	ret

vmx_launch:
	vmlaunch
	ret

vmx_exit:
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push rbp ; rsp
	push rbx
	push rdx
	push rcx
	push rax
	mov rcx,rsp
	sub rsp,28h
	call vmexit_handler
	add rsp,28h
	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp ; rsp
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
	vmresume
	ret

vmx_ret:
	pop rbp
	ret

WaitKBC:
   mov cx,0ffffh
   A20L:
   in al,64h
   test al,2
   loopnz A20L
ret

vmx_enable_a20_line:
   call WaitKBC
   mov al,0d1h
   out 64h,al
   call WaitKBC
   mov al,0dfh ; use 0dfh to enable and 0ddh to disable.
   out 60h,al
ret

vmx_disable_a20_line:
   call WaitKBC
   mov al,0d1h
   out 64h,al
   call WaitKBC
   mov al,0ddh ; use 0dfh to enable and 0ddh to disable.
   out 60h,al
ret