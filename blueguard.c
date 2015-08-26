#include <efi.h>
#include <efilib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lib_uefi.h"


EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE * sys_table)
{
    EFI_STATUS err;
    EFI_LOADED_IMAGE * loaded_image;
    EFI_FILE_HANDLE root_dir;
    /*EFI_FILE_HANDLE win_bootmgr;
    EFI_FILE_HANDLE hv_driver;*/
    //CHAR16 *loaded_image_path;
    EFI_DEVICE_PATH * win_bootmgr_path;
    EFI_DEVICE_PATH * hv_driver_path;
    EFI_HANDLE win_bootmgr_image;
    EFI_HANDLE hv_driver_image;

    init(image, sys_table);
 
    /* Store the system table for future use in other functions */
 
    /* Say hi */
    err = ST->ConOut->OutputString(ST->ConOut, L"Starting BlueGuard.\r\n");
    if (EFI_ERROR(err))
        return err;


    err = BS->OpenProtocol(image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(err)) {
        print(L"Error getting a LoadedImageProtocol handle.\r\n");
        BS->Stall(3 * 1000 * 1000);
        return err;
    }
    
    root_dir = LibOpenRoot(loaded_image->DeviceHandle);
    if (!root_dir) {
        print(L"Unable to open root directory.\r\n");
        BS->Stall(3 * 1000 * 1000);
        return EFI_LOAD_ERROR;
    }

    /*err = root_dir->Open(root_dir, &win_bootmgr, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", EFI_FILE_MODE_READ, 0ULL);
    if (EFI_ERROR(err)){
        print(L"Unable to locate Windows boot manager.\r\n");
        return EFI_LOAD_ERROR;
    }
    win_bootmgr->Close(win_bootmgr);*/

    hv_driver_path = FileDevicePath(loaded_image->DeviceHandle, L"\\EFI\\BlueGuard\\hv_driver.efi");
    if (!hv_driver_path) {
        print(L"Error getting hv_driver device path.\r\n");
        BS->Stall(3 * 1000 * 1000);
        return EFI_INVALID_PARAMETER;
    }

    err = BS->LoadImage(FALSE, image, hv_driver_path, NULL, 0, &hv_driver_image);
    if (EFI_ERROR(err)) {
        print(L"Error loading hv_driver image.\r\n");
        BS->Stall(3 * 1000 * 1000);
        return err;
    }

    err = BS->StartImage(hv_driver_image, NULL, NULL);
    if(err == EFI_SUCCESS){
      print(L"hv_driver initialized successfully.\r\n");
    }
    else{
      print(L"Initialization of hv_driver failed.\r\n");
    }

    win_bootmgr_path = FileDevicePath(loaded_image->DeviceHandle, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    if (!win_bootmgr_path) {
        print(L"Error getting bootmgfw device path.\r\n");
        BS->Stall(3 * 1000 * 1000);
        return EFI_INVALID_PARAMETER;
    }

    err = BS->LoadImage(FALSE, image, win_bootmgr_path, NULL, 0, &win_bootmgr_image);
    if (EFI_ERROR(err)) {
        print(L"Error loading bootmgfw image.\r\n");
        BS->Stall(3 * 1000 * 1000);
        return err;
    }

    print(L"Press any key to continue...\r\n");
    wait_for_key();

    print(L"Starting Windows now.\r\n");
    //BS->Stall(5 * 1000 * 1000);

    err = BS->StartImage(win_bootmgr_image, NULL, NULL);

    FreePool(win_bootmgr_path);    
    root_dir->Close(root_dir);
 
    return err;
}
