#ifndef _LIB_UEFI_
#define _LIB_UEFI_

#include <efi.h>
#include <efilib.h>
#include <stdint.h>

int strcmp(void * str1, void * str2);
int strncmp(void * str1, void * str2, int n);
void str2wstr(CHAR16 * wstr, char * str, int n);
EFI_STATUS wait_for_key(VOID);
EFI_STATUS print(CHAR16 * str);
EFI_STATUS print_uint(uint64_t n);
EFI_STATUS print_uintb(uint64_t n);
EFI_STATUS print_uintx(uint64_t n);
VOID init(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE * SystemTable);
EFI_FILE_HANDLE LibOpenRoot(IN EFI_HANDLE DeviceHandle);
EFI_DEVICE_PATH * DevicePathFromHandle(IN EFI_HANDLE Handle);
EFI_DEVICE_PATH * FileDevicePath(IN EFI_HANDLE Device OPTIONAL, IN CHAR16 * FileName);
UINTN StrSize(IN CONST CHAR16 * s1);
VOID * AllocatePool(IN UINTN Size);
VOID * AllocateZeroPool(IN UINTN Size);
VOID ZeroMem(IN VOID * Buffer, IN UINTN Size);
VOID CopyMem(IN VOID * Dest, IN CONST VOID * Src, IN UINTN len);
EFI_DEVICE_PATH * AppendDevicePath(IN EFI_DEVICE_PATH * Src1, IN EFI_DEVICE_PATH * Src2);
EFI_DEVICE_PATH * DuplicateDevicePath(IN EFI_DEVICE_PATH * DevPath);
UINTN DevicePathSize(IN EFI_DEVICE_PATH * DevPath);
VOID FreePool(IN VOID * Buffer);
UINTN DevicePathInstanceCount(IN EFI_DEVICE_PATH * DevicePath);
EFI_DEVICE_PATH * DevicePathInstance(IN OUT EFI_DEVICE_PATH  **DevicePath, OUT UINTN * Size);

#endif