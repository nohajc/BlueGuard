CC=x86_64-w64-mingw32-gcc
LD=x86_64-w64-mingw32-gcc
CFLAGS=-ffreestanding -O0 -Wall -mno-ms-bitfields
CPPFLAGS=-Ignu-efi/inc{,/x86_64,/protocol} -Ignu-efi/lib
LDFLAGS=-nostdlib -Wl,-dll -shared -e efi_main -lgcc
SUBSYS_APP=-Wl,--subsystem,10
SUBSYS_RTDRV=-Wl,--subsystem,12
ASM=nasm

VM_IMG="/media/data/Virtual Machines/vmware/Windows 8 x64/Windows 8 x64.vmdk"
MOUNT_POINT=vm_mount
EFI_PATH=$(MOUNT_POINT)/EFI/BlueGuard

all: bootx64.efi hv_driver.efi

bootx64.efi: blueguard.o data.o rtdata.o lib_uefi.o
	$(CC) $(LDFLAGS) $(SUBSYS_APP) -o $@ $^

hv_driver.efi: hv_driver.o hv_handlers.o data.o rtdata.o lib_uefi.o vmx_api.o vmx_emu.o regs.o reloc_pe.o smp.o ap_trampoline.o spinlock.o
	$(CC) $(LDFLAGS) $(SUBSYS_RTDRV) -o $@ $^

blueguard.o: blueguard.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib_uefi.o: lib_uefi.c lib_uefi.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

data.o: gnu-efi/lib/data.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

rtdata.o: gnu-efi/lib/runtime/rtdata.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

hv_driver.o: hv_driver.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

hv_handlers.o: hv_handlers.c hv_handlers.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

vmx_api.o: vmx_api.asm vmx_api.h
	$(ASM) -f win64 $< -o $@

vmx_emu.o: vmx_emu.asm vmx_emu.h
	$(ASM) -f win64 $< -o $@

regs.o: regs.asm regs.h
	$(ASM) -f win64 $< -o $@

ap_trampoline.o: ap_trampoline.asm ap_trampoline.h
	$(ASM) -f win64 $< -o $@

spinlock.o: spinlock.asm spinlock.h
	$(ASM) -f win64 $< -o $@

reloc_pe.o: reloc_pe.c reloc_pe.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

smp.o: smp.c smp.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

install:
	mkdir -p $(MOUNT_POINT)
	/opt/vmware/bin/vmware-mount $(VM_IMG) $(MOUNT_POINT)
	mkdir -p $(EFI_PATH)
	cp *.efi $(EFI_PATH)
	/opt/vmware/bin/vmware-mount -k $(VM_IMG)

clean:
	-rm *.o
	-rm bootx64.efi
	-rm hv_driver.efi

