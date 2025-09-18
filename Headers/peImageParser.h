#pragma once

#include <algorithm>
#include <Windows.h>
#include <wininet.h>
#include <winternl.h>
#include "SystemInteraction.h"
#include <iostream>
/*
#ifdef __cplusplus
extern "C" {
#endif
*/
typedef struct _WIN_CERTIFICATE {
	DWORD dwLength;
	WORD  wRevision;
	WORD  wCertificateType;
	BYTE  bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, * LPWIN_CERTIFICATE;
#ifdef PROCESSOR_ARCHITECTURE_AMD64

	#define UNINIT_PVOID_VALUE (PVOID) 0xCCCCCCCCCCCCCCCC

#endif

#ifdef _X86_

	#define UNINIT_PVOID_VALUE (PVOID) 0xCCCCCCCC;

#endif

#define TextSection ".text"

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
enum error_codes : UCHAR
{
	Success				   = 0x00,
	InvalidHandle		   = 0x01,
	InvalidBufferSize	   = 0x02,
	FileSizeIsZero		   = 0x03,
	FailedToAllocateMemory = 0x04,
	FailedToReadFile	   = 0x05,
	NullPtr				   = 0x06,
	InvalidDosSignature	   = 0x07,
	InvalidNtSignature	   = 0x08,
	FailedToFreeFromHeap   = 0x09

};
class PeFile
{

public:
	PBYTE						  pBaseOfData;
	PIMAGE_DOS_HEADER			  pImageDosHeader;
	PIMAGE_NT_HEADERS			  pImageNtHeader;
	PIMAGE_FILE_HEADER			  pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER		  pImageOptionalHeaders;
	PIMAGE_SECTION_HEADER		  pImageFirstSectionHeader;
	PIMAGE_BASE_RELOCATION		  pImageBaseRelocationDirectory;
	PIMAGE_TLS_DIRECTORY		  pImageTlsDirectory;
	PIMAGE_COR20_HEADER			  pImageCOMDataDirectory;
	PIMAGE_DELAYLOAD_DESCRIPTOR   pImageDelayLoadDirectory;
	PIMAGE_THUNK_DATA			  pImageImportAddressTable;
	PIMAGE_EXPORT_DIRECTORY		  pImageExportDirectory;
	PIMAGE_RUNTIME_FUNCTION_ENTRY pImageRunTimeFunction;
	PIMAGE_RESOURCE_DIRECTORY	  pImageResourceDirectory;
	PIMAGE_DEBUG_DIRECTORY		  pImageDebugDirectory;
	PIMAGE_IMPORT_DESCRIPTOR	  pImageImportDirectory;
	PIMAGE_LOAD_CONFIG_DIRECTORY  pImageLoadConfigurationsDirectory;
	LPWIN_CERTIFICATE			  pImageSecurityDirectory;
	HANDLE						  hHeapHandle;


	PeFile
	(
		IN     VOID
	);

	void ConsumeDataStream
	(
		IN     PBYTE pCandidateData
	);

	error_codes ParseDataFilePath
	(
		IN     LPWSTR lpPath
	);

	~PeFile
	(
		IN     VOID
	);


private:

	

	BOOLEAN						  bDidIAllocate;

	static void MapDataDirectoriesHelper
	(
		IN     LPCSTR  lpDirectoryName,
		IN     PUCHAR  puOrdinalsIndex,
		IN     UCHAR   ucOrdinals_arr[IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
		IN     UCHAR   ucOrdinal
	)
	{
		std::cout << "[+] Found a "<< lpDirectoryName <<" Directory!\n";

		ucOrdinals_arr[*puOrdinalsIndex] = ucOrdinal;

		*puOrdinalsIndex += 1;
	}

	static error_codes CheckCandidateDataValidity
	(
		IN     static PBYTE pCandidateData
	)
	{
		if (pCandidateData == nullptr) return NullPtr;

		PIMAGE_NT_HEADERS pNtHeaderTest = nullptr;
		PIMAGE_DOS_HEADER pDosHeaderTest = nullptr;

		pDosHeaderTest = reinterpret_cast<PIMAGE_DOS_HEADER>(pCandidateData);

		if (pDosHeaderTest->e_magic != IMAGE_DOS_SIGNATURE) return InvalidDosSignature;

		pNtHeaderTest = reinterpret_cast<PIMAGE_NT_HEADERS>(pCandidateData + pDosHeaderTest->e_lfanew);

		if (pNtHeaderTest->Signature != IMAGE_NT_SIGNATURE) return InvalidNtSignature;

		return Success;
	}

	static BOOLEAN CheckHandleValidity
	(

		IN     static HANDLE hCandidateHandle
	)
	{
		if (hCandidateHandle == nullptr || hCandidateHandle == INVALID_HANDLE_VALUE) return FALSE;

		return TRUE;
	}
	void MapDataDirectoriesSwitch(UCHAR ucLoopIndex, PVOID pAddressOfDirectory, PUCHAR puOrdinalArrayIndex, PUCHAR ActualDirectoriesOrdinals_arr)
	{
		switch (ucLoopIndex)
		{
		case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			pImageLoadConfigurationsDirectory = static_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Load Configurations", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr, ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_IMPORT:
			pImageImportDirectory = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Import Addresses", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr, ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_SECURITY:
			pImageSecurityDirectory = static_cast<LPWIN_CERTIFICATE>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Security", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_DEBUG:
			pImageDebugDirectory = static_cast<PIMAGE_DEBUG_DIRECTORY>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Debug", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_RESOURCE:
			pImageResourceDirectory = static_cast<PIMAGE_RESOURCE_DIRECTORY>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Resource", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			pImageDelayLoadDirectory = static_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Delayed Imports", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;


		case IMAGE_DIRECTORY_ENTRY_BASERELOC:
			pImageBaseRelocationDirectory = static_cast<PIMAGE_BASE_RELOCATION>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Base Relocations", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_EXPORT:
			pImageExportDirectory = static_cast<PIMAGE_EXPORT_DIRECTORY>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Exports", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_IAT:
			pImageImportAddressTable = static_cast<PIMAGE_THUNK_DATA>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Import Addresses Table", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_TLS:
			pImageTlsDirectory = static_cast<PIMAGE_TLS_DIRECTORY>(pAddressOfDirectory);

			MapDataDirectoriesHelper("TLS", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			pImageRunTimeFunction = static_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(pAddressOfDirectory);

			MapDataDirectoriesHelper("Runtime Functions", puOrdinalArrayIndex, ActualDirectoriesOrdinals_arr,ucLoopIndex);

			break;

		default:
			if (ucLoopIndex < 2)
			{
				switch (ucLoopIndex)
				{
				case 0:
					std::cout << "[!] The " << ucLoopIndex + 1 << "st Directory isn't Empty!\n";
					break;

				case 1:
					std::cout << "[!] The " << ucLoopIndex + 1 << "nd Directory isn't Empty!\n";
					break;

				case 2:
					std::cout << "[!] The " << ucLoopIndex + 1 << "rd Directory isn't Empty!\n";
					break;

				default:
					break;
				}
			}
			else std::cout << "[!] The " << ucLoopIndex + 1 << "th Directory isn't Empty!\n";

			ActualDirectoriesOrdinals_arr[*puOrdinalArrayIndex] = ucLoopIndex;

			*puOrdinalArrayIndex += 1;

			break;
		}

		return;
	}
	UCHAR *MapDataDirectories
	(
		IN     VOID
	)
	{
		if (pImageOptionalHeaders == nullptr) return nullptr;
		DWORD  dwVirtualAddress				  = NULL,
			   dwDirectorySize				  = NULL;
		PVOID  pAddressOfDirectory			  = nullptr;
		PUCHAR pActualDirectoriesOrdinals_arr = nullptr;
		UCHAR  ucOrdinalArrayIndex			  = NULL,
			   ucNumberOfActualDirectories    = IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
			   ActualDirectoriesOrdinals_arr[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};

		 for (UCHAR i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		 {
		 	dwVirtualAddress = pImageOptionalHeaders->DataDirectory[i].VirtualAddress;
		 	dwDirectorySize  = pImageOptionalHeaders->DataDirectory[i].Size;

			if (dwVirtualAddress == NULL || dwVirtualAddress == 0xCCCCCCCC || dwDirectorySize == 0xCCCCCCCC || dwDirectorySize == NULL)
			{
				ucNumberOfActualDirectories--;

				continue;
			}

		 	pAddressOfDirectory = pBaseOfData + dwVirtualAddress;

			MapDataDirectoriesSwitch(i, pAddressOfDirectory, &ucOrdinalArrayIndex, ActualDirectoriesOrdinals_arr);
		 }

		pActualDirectoriesOrdinals_arr = static_cast<PUCHAR>(HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, sizeof(UCHAR) * ucNumberOfActualDirectories));

		if (pActualDirectoriesOrdinals_arr == nullptr) return nullptr;

		memcpy_s(pActualDirectoriesOrdinals_arr, ucNumberOfActualDirectories * sizeof(UCHAR), ActualDirectoriesOrdinals_arr, sizeof(UCHAR) * ucNumberOfActualDirectories);

		return pActualDirectoriesOrdinals_arr;
	}

	error_codes MapFileStructures
	(
		IN     PBYTE   pFileData,
		IN     const BOOLEAN bValidated
	)
	{
		error_codes ecStatus = Success;

		if (bValidated == FALSE)
		{
			ecStatus = CheckCandidateDataValidity(pFileData);

			if (ecStatus != Success)
			{
				if (this->bDidIAllocate == TRUE && HeapFree(hHeapHandle, NULL, pFileData) == FALSE) return FailedToFreeFromHeap;

				return ecStatus;
			}
		}

		pBaseOfData				 = pFileData;
		pImageDosHeader			 = reinterpret_cast<PIMAGE_DOS_HEADER>(pFileData);
		pImageNtHeader			 = reinterpret_cast<PIMAGE_NT_HEADERS>(pBaseOfData + pImageDosHeader->e_lfanew);
		pImageFirstSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pImageNtHeader) + sizeof(IMAGE_NT_HEADERS));
		pImageFileHeader		 = &pImageNtHeader->FileHeader;
		pImageOptionalHeaders	 = &pImageNtHeader->OptionalHeader;

		MapDataDirectories();

		return ecStatus;
	}

};

BOOLEAN FetchImageBaseRelocationDirectory
(
	IN				PBYTE				   pImageData,
	   OUT			PIMAGE_BASE_RELOCATION *pImageBaseRelocationDirectory_tBaseAddress
);

PBYTE FetchImageData
(
	IN				LPWSTR lpImagePath,
		   OPTIONAL HANDLE hHeapHandle,
	   OUT OPTIONAL PDWORD pdwImageSize
);

BOOLEAN FetchImageDosHeader
(
	IN				PBYTE			  pImageData,
	   OUT			PIMAGE_DOS_HEADER* pImageDOSHeader_tBaseAddress
);

BOOLEAN FetchImageExportDirectory
(
	IN				PBYTE					pImageData,
	   OUT			PIMAGE_EXPORT_DIRECTORY *pImageFileExportDirectory_tBaseAddress
);

BOOLEAN FetchImageFileHeader
(
	IN				PBYTE			   pImageData,
	   OUT			PIMAGE_FILE_HEADER *pImageFileHeader_tBaseAddress
);

BOOLEAN FetchImageImportDirectory
(
	IN				PBYTE					 pImageData,
	   OUT			PIMAGE_IMPORT_DESCRIPTOR *pImageImportDirectory_tBaseAddress
);

BOOLEAN FetchImageNtHeaders
(
	IN				PBYTE			   pImageData,
	   OUT			PIMAGE_NT_HEADERS *pImageNtHeaders_tBaseAddress
);

BOOLEAN FetchImageOptionalHeaders
(
	IN				PBYTE					pImageData,
	   OUT			PIMAGE_OPTIONAL_HEADER *pImageOptionalHeaders_tBaseAddress
);

BOOLEAN FetchImageSection
(
	IN				PBYTE 				   pImageData,
	   OUT			PIMAGE_SECTION_HEADER* pImageSectionHeader_tBaseAddress
);

BOOLEAN FetchImageTlsDirectory
(
	IN				PBYTE				 pImageData,
	   OUT			PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
);

BOOLEAN FetchImageRtFuncDirectory
(
	IN				PBYTE						  pImageData,
	   OUT			PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory_tBaseAddress
);

LPWSTR FetchImagePathFromRemoteProcess
(
	IN				HANDLE  hTargetProcessHandle
);

PPROCESS_BASIC_INFORMATION FetchRemotePBINtQuerySystemInformation
(
	IN				HANDLE hTargetImageProcessHandle,
	IN     OPTIONAL HANDLE hHeapHandle
);

PPEB FetchRemoteProcessEnvironmentBlock
(
	IN				HANDLE					   hTargetImageProcessHandle,
	IN				HANDLE					   hHeapHandle,
	IN     OPTIONAL PPROCESS_BASIC_INFORMATION pProcessBasicInformation_t
);

PRTL_USER_PROCESS_PARAMETERS FetchRemoteRTLUserProcessParameters
(
	IN				HANDLE hTargetImageProcessHandle,
	IN				HANDLE hHeapHandle,
	IN     OPTIONAL PPEB   pProcessEnvironmentBlock_t
);

PIMAGE_SECTION_HEADER FindImageSectionHeaderByName
(
	IN			   LPCSTR				 pTagetSectionName,
	IN			   PBYTE				 pImageData
);


BOOLEAN ReadStructFromProcess
(
	IN				HANDLE hTargetProcess, 
	IN				PVOID  pStructBaseAddress, 
	IN				DWORD  dwBufferSize,
	IN				HANDLE hHeapHandle,
	   OUT			PVOID *pReadBufferAddress
);

/*
#ifdef __cplusplus
}
#endif
*/