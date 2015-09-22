global disable_pic

section .text

disable_pic:
	; Remap PIC IRQ's
	mov al, 0x11			; begin PIC 1 initialization
	out 0x20, al	
	mov al, 0x11			; begin PIC 2 initialization
	out 0xA0, al
	mov al, 0x20			; IRQ 0-7: interrupts 20h-27h
	out 0x21, al
	mov al, 0x28			; IRQ 8-15: interrupts 28h-2Fh
	out 0xA1, al
	mov al, 4
	out 0x21, al
	mov al, 2
	out 0xA1, al
	mov al, 1
	out 0x21, al
	out 0xA1, al

	; Mask all PIC interrupts
	mov al, 0xFF
	out 0x21, al
	out 0xA1, al
	ret