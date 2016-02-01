; 16-bit real mode
0x1000:      jmp    0x1640
0x1640:      cli
0x1641:      sub    eax,eax
0x1644:      mov    ax,cs
0x1646:      mov    ds,ax
0x1648:      shl    eax,0x4
0x164c:      mov    edi,eax
0x164f:  o32 lgdt   [dword 0xc] ; limit & base at 0x100c - limit = 0x3F, base = 0x1018
0x1658:      mov    eax,cr0
0x165b:      or     eax,0x11
0x165f:      mov    cr0,eax
0x1662:      mov    ax,0x20
0x1665:      mov    ds,ax ; ds = 0x20
0x1667:      jmp dword far [edi+0x60] ; dst addr stored at 0x1060: 0x30:0x166c, cs = 0x30 (from 0x1064)
; 32-bit protected mode
0x166c:      mov    eax,[edi+0xa8] ; CR4 value stored at 0x10a8
0x1672:      mov    cr4,eax
0x1675:      mov    eax,[edi+0x58] ; CR3 value stored at 0x1058
0x1678:      mov    cr3,eax
0x167b:      test   dword [edi+0x8],0x1 ; if (*(uint32_t*)0x1008 & 1 == 1)
0x1682:      jz     0x1690
0x1684:      mov    ecx,0x1a0      ; IA32_MISC_ENABLE
0x1689:      rdmsr
0x168b:      and    edx,0xfffffffb ; mask 34th bit (Execute Disable Bit) - enabling XD bit feature for data only pages
0x168e:      wrmsr
0x1690:      mov    ecx,0xc0000080 ; IA32_EFER
0x1695:      rdmsr
0x1697:      or     eax,[edi+0x88] ; EFER low or mask at 0x1088: SCE (SYSCALL enable), LME (Long mode enable), NXE (XD Bit Enable)
0x169d:      or     edx,[edi+0x8c] ; EFER high or mask at 0x108c: reserved (0x0)
0x16a3:      wrmsr
0x16a5:      mov    eax,[edi+0x90] ; CR0 value stored at 0x1090
0x16ab:      mov    cr0,eax
0x16ae:      jmp    dword far [edi+0x66] ; dst addr stored at 0x1066: 0x10:0x16b1, cs = 0x10 (from 0x106A)
; 64-bit long mode
0x16b1:      mov    edi,edi
0x16b3:      mov    rcx,[rdi+0x70] ; kernel entry point address stored at 0x1070, rcx = *0x1070
0x16b7:      mov    rax,[rdi+0xa0] ; rax = *0x10a0
0x16be:      mov    rdi,[rdi+0x78] ; rdi = *0x1078
0x16c2:      jmp    rcx
