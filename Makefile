CC=x86_64-w64-mingw32-gcc
LD=x86_64-w64-mingw32-gcc
CFLAGS=-ffreestanding -O0 -Wall -Wno-unused-label -mno-ms-bitfields -g
CPPFLAGS=-Ignu-efi/inc{,/x86_64,/protocol} -Ignu-efi/lib
LDFLAGS=-nostdlib -Wl,-dll -shared -e efi_main -lgcc
SUBSYS_APP=-Wl,--subsystem,10
SUBSYS_RTDRV=-Wl,--subsystem,12
ASM=nasm

VM_IMG="/media/data/Virtual Machines/vmware/Windows 8 x64/Windows 8 x64.vmdk"
KVM_IMG="/media/data/Virtual Machines/kvm_win8.1.vmdk"
MOUNT_POINT=vm_mount
EFI_PATH=$(MOUNT_POINT)/EFI/BlueGuard

all: bootx64.efi hv_driver.efi

bootx64.efi: blueguard.o data.o rtdata.o lib_uefi.o
	$(CC) $(LDFLAGS) $(SUBSYS_APP) -o $@ $^

hv_driver.efi: hv_driver.o hv_handlers.o data.o rtdata.o lib_uefi.o vmx_api.o vmx_api_c.o vmx_emu.o vm_setup.o regs.o reloc_pe.o smp.o ap_trampoline.o spinlock.o pic.o string.o realmode_emu.o
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

vm_setup.o: vm_setup.c vm_setup.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

realmode_emu.o: realmode_emu.c realmode_emu.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

vmx_api_c.o: vmx_api.c vmx_api.h
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

pic.o: pic.asm pic.h
	$(ASM) -f win64 $< -o $@

reloc_pe.o: reloc_pe.c reloc_pe.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

smp.o: smp.c smp.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

string.o: string.c string.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

install:
	mkdir -p $(MOUNT_POINT)
	/opt/vmware/bin/vmware-mount $(VM_IMG) $(MOUNT_POINT)
	mkdir -p $(EFI_PATH)
	cp *.efi $(EFI_PATH)
	/opt/vmware/bin/vmware-mount -k $(VM_IMG)

hw_install:
	mkdir -p /mnt/efi
	mount /dev/sda1 /mnt/efi
	cp bootx64.efi /mnt/efi/EFI/BlueGuard/blueguard.efi
	cp hv_driver.efi /mnt/efi/EFI/BlueGuard/hv_driver.efi
	umount /mnt/efi

kvm_install:
	mkdir -p $(MOUNT_POINT)
	/opt/vmware/bin/vmware-mount $(KVM_IMG) 2 $(MOUNT_POINT)
	mkdir -p $(EFI_PATH)
	cp *.efi $(EFI_PATH)
	/opt/vmware/bin/vmware-mount -k $(KVM_IMG)

umount:
	/opt/vmware/bin/vmware-mount -k $(VM_IMG)

kvm_umount:
	/opt/vmware/bin/vmware-mount -k $(KVM_IMG)


clean:
	-rm *.o
	-rm bootx64.efi
	-rm hv_driver.efi

