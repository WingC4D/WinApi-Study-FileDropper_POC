#pragma once
#include <Windows.h>

#ifdef PROCESSOR_ARCHITECTURE_AMD64

	#define UNINIT_PVOID_VALUE (PVOID)0xCCCCCCCCCCCCCCCC

#endif

#ifdef _X86_

	#define UNINIT_PVOID_VALUE (PVOID)0xCCCCCCCC;

#endif

BOOLEAN FetchImageData
(
	IN	   LPWSTR lpImagePath,
	IN OUT HANDLE hHeapHandle,
	   OUT PBYTE *pImageDataBaseAddress		   
);

BOOLEAN FetchImageDosHeader
(
	IN     PBYTE			  pImageData,
	   OUT PIMAGE_DOS_HEADER* pImageDOSHeader_tBaseAddress
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

BOOLEAN FetchImageTlsDirectory
(
	IN     PBYTE				 pImageData,
	   OUT PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
);

BOOLEAN FetchImageRtFuncDirectory
(
	IN     PBYTE						  pImageData,
	   OUT PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory
);



// PIMAGE_SECTION_HEADER PIMAGE_EXPORT_DIRECTORY PIMAGE_IMPORT_DESCRIPTOR PIMAGE_TLS_DIRECTORY PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_BASE_RELOCATION