#ifndef _RELOC_PE_
#define _RELOC_PE_

#include <stdint.h>

typedef struct _IMAGE_DOS_HEADER{
     uint16_t e_magic;
     uint16_t e_cblp;
     uint16_t e_cp;
     uint16_t e_crlc;
     uint16_t e_cparhdr;
     uint16_t e_minalloc;
     uint16_t e_maxalloc;
     uint16_t e_ss;
     uint16_t e_sp;
     uint16_t e_csum;
     uint16_t e_ip;
     uint16_t e_cs;
     uint16_t e_lfarlc;
     uint16_t e_ovno;
     uint16_t e_res[4];
     uint16_t e_oemid;
     uint16_t e_oeminfo;
     uint16_t e_res2[10];
     int32_t  e_lfanew;
} __attribute__((packed, aligned(4))) IMAGE_DOS_HEADER;


typedef struct _IMAGE_FILE_HEADER{
  uint16_t  Machine;
  uint16_t  NumberOfSections;
  uint32_t  TimeDateStamp;
  uint32_t  PointerToSymbolTable;
  uint32_t  NumberOfSymbols;
  uint16_t  SizeOfOptionalHeader;
  uint16_t  Characteristics;
} __attribute__((packed, aligned(4))) IMAGE_FILE_HEADER;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES     16

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

typedef struct _IMAGE_DATA_DIRECTORY{
  uint32_t VirtualAddress;
  uint32_t Size;
} __attribute__((packed, aligned(4))) IMAGE_DATA_DIRECTORY;


typedef struct _IMAGE_OPTIONAL_HEADER64{
 uint16_t       Magic;
 uint8_t        MajorLinkerVersion;
 uint8_t        MinorLinkerVersion;
 uint32_t       SizeOfCode;
 uint32_t       SizeOfInitializedData;
 uint32_t       SizeOfUninitializedData;
 uint32_t       AddressOfEntryPoint;
 uint32_t       BaseOfCode;
 uint64_t       ImageBase;
 uint32_t       SectionAlignment;
 uint32_t       FileAlignment;
 uint16_t       MajorOperatingSystemVersion;
 uint16_t       MinorOperatingSystemVersion;
 uint16_t       MajorImageVersion;
 uint16_t       MinorImageVersion;
 uint16_t       MajorSubsystemVersion;
 uint16_t       MinorSubsystemVersion;
 uint32_t       Win32VersionValue;
 uint32_t       SizeOfImage;
 uint32_t       SizeOfHeaders;
 uint32_t       CheckSum;
 uint16_t       Subsystem;
 uint16_t       DllCharacteristics;
 uint64_t       SizeOfStackReserve;
 uint64_t       SizeOfStackCommit;
 uint64_t       SizeOfHeapReserve;
 uint64_t       SizeOfHeapCommit;
 uint32_t       LoaderFlags;
 uint32_t       NumberOfRvaAndSizes;
 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__((packed, aligned(4))) IMAGE_OPTIONAL_HEADER64;


typedef struct _IMAGE_NT_HEADERS64{
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} __attribute__((packed, aligned(4))) IMAGE_NT_HEADERS64;


#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10

typedef struct _IMAGE_BASE_RELOCATION{
    uint32_t   VirtualAddress;
    uint32_t   SizeOfBlock;
	uint16_t   TypeOffset[1];
} __attribute__((packed, aligned(4))) IMAGE_BASE_RELOCATION;


int64_t reloc_image(IMAGE_DOS_HEADER * img, uint64_t new_base);

#endif