#pragma once

#include <Windows.h>
#include <winternl.h>
#include "SystemInteraction.h"
/*
#ifdef __cplusplus
extern "C" {
#endif
*/
#ifdef PROCESSOR_ARCHITECTURE_AMD64

	#define UNINIT_PVOID_VALUE (PVOID)0xCCCCCCCCCCCCCCCC

#endif

#ifdef _X86_

	#define UNINIT_PVOID_VALUE (PVOID)0xCCCCCCCC;

#endif

typedef NTSTATUS(NTAPI* fnNtQueryProcessInformation)
(
    IN              HANDLE           ProcessHandle,
    IN              PROCESSINFOCLASS ProcessInformationClass,
       OUT          PVOID            ProcessInformation,
    IN              ULONG            ProcessInformationLength,
       OUT OPTIONAL PULONG           ReturnLength
    );

__kernel_entry NTSTATUS NtQueryProcessInformation
(
    IN              HANDLE           ProcessHandle,
    IN              PROCESSINFOCLASS ProcessInformationClass,
       OUT          PVOID            ProcessInformation,
    IN              ULONG            ProcessInformationLength,
       OUT OPTIONAL PULONG           ReturnLength
);

BOOLEAN FetchImageBaseRelocationDirectory
(
	IN     PBYTE				   pImageData,
	   OUT PIMAGE_BASE_RELOCATION *pImageBaseRelocationDirectory_tBaseAddress
);

BOOLEAN FetchImageData
(
	IN				LPWSTR lpImagePath,
		   OPTIONAL HANDLE hHeapHandle,
	   OUT			PBYTE *pImageDataBaseAddress		   
);

BOOLEAN FetchImageDosHeader
(
	IN     PBYTE			  pImageData,
	   OUT PIMAGE_DOS_HEADER* pImageDOSHeader_tBaseAddress
);

BOOLEAN FetchImageExportDirectory
(
	IN     PBYTE					pImageData,
	   OUT PIMAGE_EXPORT_DIRECTORY *pImageFileExportDirectory_tBaseAddress
);

BOOLEAN FetchImageFileHeader
(
	IN     PBYTE			   pImageData,
	   OUT PIMAGE_FILE_HEADER *pImageFileHeader_tBaseAddress
);

BOOLEAN FetchImageImportDirectory
(
	IN     PBYTE					 pImageData,
	   OUT PIMAGE_IMPORT_DESCRIPTOR *pImageImportDirectory_tBaseAddress
);

BOOLEAN FetchImageNtHeaders
(
	IN		PBYTE			   pImageData,
	   OUT	PIMAGE_NT_HEADERS *pImageNtHeaders_tBaseAddress
);

BOOLEAN FetchImageOptionalHeaders
(
	IN		PBYTE					pImageData,
	   OUT	PIMAGE_OPTIONAL_HEADER *pImageOptionalHeaders_tBaseAddress
);

BOOLEAN FetchImageSection
(
	IN     PBYTE 				   pImageData,
	   OUT PIMAGE_SECTION_HEADER* pImageSectionHeader_tBaseAddress
);

BOOLEAN FetchImageTlsDirectory
(
	IN     PBYTE				 pImageData,
	   OUT PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
);

BOOLEAN FetchImageRtFuncDirectory
(
	IN     PBYTE						  pImageData,
	   OUT PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory_tBaseAddress
);

BOOLEAN FetchPathFromRunningProcess
(
	IN     HANDLE  hTargetImageProcessHandle,
	   OUT LPWSTR *pImagePathBufferAddress
);

PPROCESS_BASIC_INFORMATION FetchPBINtQuerySystemInformation
(
	IN     HANDLE  hTargetImageProcessHandle
);

PPEB FetchRemoteProcessEnvironmentBlock
(
	IN	   OPTIONAL	HANDLE					   hTargetImageProcessHandle,
	IN				HANDLE					   hHeapHandle,
	IN     OPTIONAL PPROCESS_BASIC_INFORMATION pProcessBasicInformation_t
);

PIMAGE_SECTION_HEADER FindImageSectionHeaderByName
(
	IN			   LPCSTR				 pTagetSectionName,
	IN	  OPTIONAL PIMAGE_SECTION_HEADER pImageTextSection,
	IN	  OPTIONAL WORD					 number_of_sections,
	IN	  OPTIONAL PBYTE				 pImageData
);

BOOLEAN ReadStructFromProcess
(
	IN     HANDLE hTargetProcess, 
	IN     PVOID  pStructBaseAddress, 
	IN     DWORD  dwBufferSize,
	IN     HANDLE hHeapHandle,
	   OUT PVOID *pReadBufferAddress
);

/*
#ifdef __cplusplus
}
#endif
*/