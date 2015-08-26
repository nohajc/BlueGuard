#include "lib_uefi.h"

EFI_STATUS print(CHAR16 * str){
    return ST->ConOut->OutputString(ST->ConOut, str);
}

int strcmp(void * a, void * b){
    char * str1 = a;
    char * str2 = b;
    while(*str1 != '\0' || *str2 != '\0')
    {
        if(*str1 > *str2)
            return 1;
        if(*str1 < *str2)
            return -1;
        ++str1;
        ++str2;
    }
    return 0;
}

int strncmp(void * a, void * b, int n){
    int i = 0;
    char * str1 = a;
    char * str2 = b;
    while(i < n && (*str1 != '\0' || *str2 != '\0'))
    {
        if(*str1 > *str2)
            return 1;
        if(*str1 < *str2)
            return -1;
        ++str1;
        ++str2;
        ++i;
    }
    return 0;
}

void str2wstr(CHAR16 * wstr, char * str, int n){
    int i = 0;
    char * wstr_ptr = (char*)wstr;
    while(i < n && *str){
        *wstr_ptr++ = *str++;
        *wstr_ptr++ = 0;
        ++i;
    }
}

EFI_STATUS print_uint(uint64_t n){
    CHAR16 num_str[256] = {0};
    EFI_STATUS st = EFI_SUCCESS;

    int i = 255;
    if(n == 0){
        return print(L"0");
    }
    while(n > 0){
        --i;
        num_str[i] = (n % 10) + '0';
        n /= 10;
    }
    st = print(num_str + i);

    return st;
}

EFI_STATUS print_uintb(uint64_t n){
    CHAR16 num_str[256] = {0};
    EFI_STATUS st = EFI_SUCCESS;

    int i = 255;
    if(n == 0){
        return print(L"0");
    }
    while(n > 0){
        --i;
        num_str[i] = (n % 2) + '0';
        n /= 2;
    }
    st = print(num_str + i);

    return st;
}

EFI_STATUS print_uintx(uint64_t n){
    CHAR16 num_str[256] = {0};
    EFI_STATUS st = EFI_SUCCESS;

    int i = 255, digit;
    if(n == 0){
        return print(L"0");
    }
    while(n > 0){
        --i;
        digit = n % 16;
        if(digit < 10){
            num_str[i] = digit + '0';
        }
        else{
            num_str[i] = digit - 10 + 'A';
        }
        n /= 16;
    }
    st = print(num_str + i);

    return st;
}

EFI_STATUS wait_for_key(VOID){
    EFI_STATUS Status;
    EFI_INPUT_KEY Key;
    /* Now wait for a keystroke before continuing, otherwise your
       message will flash off the screen before you see it.
 
       First, we need to empty the console input buffer to flush
       out any keystrokes entered before this point */
    Status = ST->ConIn->Reset(ST->ConIn, FALSE);
    if (EFI_ERROR(Status))
        return Status;
 
    /* Now wait until a key becomes available.  This is a simple
       polling implementation.  You could try and use the WaitForKey
       event instead if you like */
    while ((Status = ST->ConIn->ReadKeyStroke(ST->ConIn, &Key)) == EFI_NOT_READY);

    return Status;
}

VOID init(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE * SystemTable){
    EFI_LOADED_IMAGE * LoadedImage;
    EFI_STATUS Status;

    //
    // Set up global pointer to the system table, boot services table,
    // and runtime services table
    //

    ST = SystemTable;
    BS = SystemTable->BootServices;
    RT = SystemTable->RuntimeServices;

    //
    // Initialize pool allocation type
    //

    if (ImageHandle) {
        Status = BS->HandleProtocol(
                        ImageHandle, 
                        &LoadedImageProtocol,
                        (VOID*)&LoadedImage
                        );

        if (!EFI_ERROR(Status)) {
            PoolAllocationType = LoadedImage->ImageDataType;
        }
    }
}

EFI_FILE_HANDLE LibOpenRoot(IN EFI_HANDLE DeviceHandle)
{
    EFI_STATUS                  Status;
    EFI_FILE_IO_INTERFACE       *Volume;
    EFI_FILE_HANDLE             File;


    //
    // File the file system interface to the device
    //

    Status = BS->HandleProtocol(DeviceHandle, &FileSystemProtocol, (VOID*)&Volume);

    //
    // Open the root directory of the volume 
    //

    if (!EFI_ERROR(Status)) {
        Status = Volume->OpenVolume(Volume, &File);
    }

    //
    // Done
    //

    return EFI_ERROR(Status) ? NULL : File;
}

EFI_DEVICE_PATH * DevicePathFromHandle(IN EFI_HANDLE Handle)
{
    EFI_STATUS          Status;
    EFI_DEVICE_PATH     *DevicePath;

    Status = BS->HandleProtocol(Handle, &DevicePathProtocol, (VOID*)&DevicePath);
    if (EFI_ERROR(Status)) {
        DevicePath = NULL;
    }

    return DevicePath;
}

UINTN
StrSize (
    IN CONST CHAR16   *s1
    )
// string size
{
    UINTN len;
    
    for (len=0; *s1; s1+=1, len+=1) ;
    return (len + 1) * sizeof(CHAR16);
}

VOID *
AllocatePool (
    IN UINTN                Size
    )
{
    EFI_STATUS              Status;
    VOID                    *p;

    Status = BS->AllocatePool(PoolAllocationType, Size, &p);
    if (EFI_ERROR(Status)) {
        DEBUG((D_ERROR, "AllocatePool: out of pool  %x\n", Status));
        p = NULL;
    }
    return p;
}

VOID *
AllocateZeroPool (
    IN UINTN                Size
    )
{
    VOID                    *p;

    p = AllocatePool (Size);
    if (p) {
        ZeroMem (p, Size);
    }

    return p;
}

VOID
ZeroMem (
    IN VOID     *Buffer,
    IN UINTN    Size
    )
{
    INT8        *pt;

    pt = Buffer;
    while (Size--) {
        *(pt++) = 0;
    }
}

/*
#define SetDevicePathNodeLength(a,l) {                  \
            (a)->Length[0] = (UINT8) (l);               \
            (a)->Length[1] = (UINT8) ((l) >> 8);        \
            }
*/

VOID
CopyMem (
    IN VOID     *Dest,
    IN CONST VOID     *Src,
    IN UINTN    len
    )
{
    CHAR8   *d;
    CONST CHAR8 *s = Src;
    d = Dest;
    while (len--) {
        *(d++) = *(s++);
    }
}

// #define NextDevicePathNode(a)       ( (EFI_DEVICE_PATH *) ( ((UINT8 *) (a)) + DevicePathNodeLength(a)))
/*
 #define SetDevicePathEndNode(a)  {                      \
            (a)->Type = END_DEVICE_PATH_TYPE;           \
            (a)->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;     \
            (a)->Length[0] = sizeof(EFI_DEVICE_PATH);   \
            (a)->Length[1] = 0;                         \
            }
*/

EFI_DEVICE_PATH *
DuplicateDevicePath (
    IN EFI_DEVICE_PATH  *DevPath
    )
{
    EFI_DEVICE_PATH     *NewDevPath;
    UINTN               Size;    


    //
    // Compute the size
    //

    Size = DevicePathSize (DevPath);

    //
    // Make a copy
    //

    NewDevPath = AllocatePool (Size);
    if (NewDevPath) {
        CopyMem (NewDevPath, DevPath, Size);
    }

    return NewDevPath;
}

UINTN
DevicePathSize (
    IN EFI_DEVICE_PATH  *DevPath
    )
{
    EFI_DEVICE_PATH     *Start;

    //
    // Search for the end of the device path structure
    //    

    Start = DevPath;
    while (!IsDevicePathEnd(DevPath)) {
        DevPath = NextDevicePathNode(DevPath);
    }

    //
    // Compute the size
    //

    return ((UINTN) DevPath - (UINTN) Start) + sizeof(EFI_DEVICE_PATH);
}

EFI_DEVICE_PATH *
DevicePathInstance (
    IN OUT EFI_DEVICE_PATH  **DevicePath,
    OUT UINTN               *Size
    )
{
    EFI_DEVICE_PATH         *Start, *Next, *DevPath;
    UINTN                   Count;

    DevPath = *DevicePath;
    Start = DevPath;

    if (!DevPath) {
        return NULL;
    }

    //
    // Check for end of device path type
    //    

    for (Count = 0; ; Count++) {
        Next = NextDevicePathNode(DevPath);

        if (IsDevicePathEndType(DevPath)) {
            break;
        }

        if (Count > 01000) {
            //
            // BugBug: Debug code to catch bogus device paths
            //
            //DEBUG((D_ERROR, "DevicePathInstance: DevicePath %x Size %d", *DevicePath, ((UINT8 *) DevPath) - ((UINT8 *) Start) ));
            //DumpHex (0, 0, ((UINT8 *) DevPath) - ((UINT8 *) Start), Start);
            //break;
        }

        DevPath = Next;
    }

    ASSERT (DevicePathSubType(DevPath) == END_ENTIRE_DEVICE_PATH_SUBTYPE ||
            DevicePathSubType(DevPath) == END_INSTANCE_DEVICE_PATH_SUBTYPE);

    //
    // Set next position
    //

    if (DevicePathSubType(DevPath) == END_ENTIRE_DEVICE_PATH_SUBTYPE) {
        Next = NULL;
    }

    *DevicePath = Next;

    //
    // Return size and start of device path instance
    //

    *Size = ((UINT8 *) DevPath) - ((UINT8 *) Start);
    return Start;
}

UINTN
DevicePathInstanceCount (
    IN EFI_DEVICE_PATH      *DevicePath
    )
{
    UINTN       Count, Size;

    Count = 0;
    while (DevicePathInstance(&DevicePath, &Size)) {
        Count += 1;
    }

    return Count;
}

EFI_DEVICE_PATH *
AppendDevicePath (
    IN EFI_DEVICE_PATH  *Src1,
    IN EFI_DEVICE_PATH  *Src2
    )
// Src1 may have multiple "instances" and each instance is appended
// Src2 is appended to each instance is Src1.  (E.g., it's possible
// to append a new instance to the complete device path by passing 
// it in Src2)
{
    UINTN               Src1Size, Src1Inst, Src2Size, Size;
    EFI_DEVICE_PATH     *Dst, *Inst;
    UINT8               *DstPos;

    //
    // If there's only 1 path, just duplicate it
    //

    if (!Src1) {
        ASSERT (!IsDevicePathUnpacked (Src2));
        return DuplicateDevicePath (Src2);
    }

    if (!Src2) {
        ASSERT (!IsDevicePathUnpacked (Src1));
        return DuplicateDevicePath (Src1);
    }

    //
    // Verify we're not working with unpacked paths
    //

//    ASSERT (!IsDevicePathUnpacked (Src1));
//    ASSERT (!IsDevicePathUnpacked (Src2));

    //
    // Append Src2 to every instance in Src1
    //

    Src1Size = DevicePathSize(Src1);
    Src1Inst = DevicePathInstanceCount(Src1);
    Src2Size = DevicePathSize(Src2);
    Size = Src1Size * Src1Inst + Src2Size;
    
    Dst = AllocatePool (Size);
    if (Dst) {
        DstPos = (UINT8 *) Dst;

        //
        // Copy all device path instances
        //

        while ((Inst = DevicePathInstance (&Src1, &Size))) {

            CopyMem(DstPos, Inst, Size);
            DstPos += Size;

            CopyMem(DstPos, Src2, Src2Size);
            DstPos += Src2Size;

            CopyMem(DstPos, EndInstanceDevicePath, sizeof(EFI_DEVICE_PATH));
            DstPos += sizeof(EFI_DEVICE_PATH);
        }

        // Change last end marker
        DstPos -= sizeof(EFI_DEVICE_PATH);
        CopyMem(DstPos, EndDevicePath, sizeof(EFI_DEVICE_PATH));
    }

    return Dst;
}

VOID
FreePool (
    IN VOID                 *Buffer
    )
{
    BS->FreePool(Buffer);
}

EFI_DEVICE_PATH *
FileDevicePath (
    IN EFI_HANDLE       Device  OPTIONAL,
    IN CHAR16           *FileName
    )
/*++

    N.B. Results are allocated from pool.  The caller must FreePool
    the resulting device path structure

--*/
{
    UINTN                   Size;
    FILEPATH_DEVICE_PATH    *FilePath;
    EFI_DEVICE_PATH         *Eop, *DevicePath;    

    Size = StrSize(FileName);
    FilePath = AllocateZeroPool (Size + SIZE_OF_FILEPATH_DEVICE_PATH + sizeof(EFI_DEVICE_PATH));
    DevicePath = NULL;

    if (FilePath) {

        //
        // Build a file path
        //

        FilePath->Header.Type = MEDIA_DEVICE_PATH;
        FilePath->Header.SubType = MEDIA_FILEPATH_DP;
        SetDevicePathNodeLength (&FilePath->Header, Size + SIZE_OF_FILEPATH_DEVICE_PATH);
        CopyMem (FilePath->PathName, FileName, Size);
        Eop = NextDevicePathNode(&FilePath->Header);
        SetDevicePathEndNode(Eop);

        //
        // Append file path to device's device path
        //

        DevicePath = (EFI_DEVICE_PATH *) FilePath;
        if (Device) {
            DevicePath = AppendDevicePath (
                            DevicePathFromHandle(Device),
                            DevicePath
                            );

            FreePool(FilePath);
        }
    }

    return DevicePath;
}