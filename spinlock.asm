global acquire_lock
global release_lock

section .text

acquire_lock:
	mov eax,0
	lock bts [ecx],eax
	jc spin
	ret

spin:
	pause
	test dword [ecx],1
	jnz spin
	jmp acquire_lock

release_lock:
	mov dword [ecx],0
	ret