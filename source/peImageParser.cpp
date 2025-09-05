#include "peImageParser.h"

namespace anonymous
{

static BOOLEAN CheckBuffer
(
	IN     DWORD  dwSizeToAllocate,
	IN     HANDLE hHeapHandle,
	   OUT PVOID *pBufferAddress
)
{
	if (!dwSizeToAllocate || !hHeapHandle || !pBufferAddress) return FALSE;

	if (pBufferAddress != nullptr && *pBufferAddress != UNINIT_PVOID_VALUE && *pBufferAddress != nullptr) return TRUE;

	*pBufferAddress = HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, dwSizeToAllocate);

	if (*pBufferAddress == nullptr) return FALSE;

	return TRUE;
}

static UCHAR CheckDataForDOSHeader
(
	IN	  PBYTE	 pCandidateData
)
{
	if (pCandidateData == nullptr) return 1;

	PIMAGE_DOS_HEADER pPotentialHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pCandidateData);

	if (pPotentialHeader->e_magic != IMAGE_DOS_SIGNATURE) return 2;

	return 0;
}

BOOLEAN CheckHeapHandle
(
	IN OUT PHANDLE phHeapHandle
)
{
	if (!phHeapHandle) return FALSE;

	if (*phHeapHandle == nullptr || *phHeapHandle == INVALID_HANDLE_VALUE || *phHeapHandle == nullptr)
		
		if ((*phHeapHandle = GetProcessHeap()) == INVALID_HANDLE_VALUE) return FALSE;

	return TRUE;
}

}

BOOLEAN FetchPathFromRunningProcess
(
	IN     HANDLE  hTargetImageProcessHandle,
	   OUT LPWSTR *pImagePathBufferAddress
)
{
	ULONG 						 NtQueryReturnValue      	 = 0;
	NTSTATUS					 NtStatus					 = 0;
	PVOID						 pProcessPathBuffer			 = NULL;
	fnNtQueryProcessInformation  NtQueryInformationProcess 	 = NULL;
	PPEB						 process_environment_block_t = NULL;
	PRTL_USER_PROCESS_PARAMETERS process_user_parameters     = NULL;
	PROCESS_BASIC_INFORMATION	 process_basic_info_t        = { 0 };
	HANDLE						 hHeapHandle			 	 = INVALID_HANDLE_VALUE;

	if ((hHeapHandle = GetProcessHeap()) == INVALID_HANDLE_VALUE) return FALSE;
		
	if ((NtQueryInformationProcess = reinterpret_cast<fnNtQueryProcessInformation>(GetProcessAddressReplacement(GetModuleHandleReplacement(const_cast<LPWSTR>(L"NTDLL.dll")), const_cast<LPSTR>("NtQueryInformationProcess")))) == nullptr) return FALSE;

	if (NtQueryInformationProcess(hTargetImageProcessHandle, ProcessBasicInformation, &process_basic_info_t, sizeof(PROCESS_BASIC_INFORMATION), &NtQueryReturnValue) != 0x0) return FALSE;

	if (!anonymous::CheckBuffer(sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID *>(&process_environment_block_t))) return FALSE;

	if (!ReadStructFromProcess(hTargetImageProcessHandle, process_basic_info_t.PebBaseAddress, sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID *>(&process_environment_block_t))) goto FailCleanup;

	if (!anonymous::CheckBuffer(sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID *>(&process_user_parameters))) return FALSE;

	if (!ReadStructFromProcess(hTargetImageProcessHandle, process_environment_block_t->ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, hHeapHandle, reinterpret_cast<PVOID*>(&process_user_parameters))) goto FailCleanup;

	if (!ReadStructFromProcess( hTargetImageProcessHandle, process_user_parameters->ImagePathName.Buffer, process_user_parameters->ImagePathName.Length, hHeapHandle, reinterpret_cast<PVOID*>(pImagePathBufferAddress))) return FALSE;

	HeapFree(hHeapHandle, 0, process_environment_block_t);

	process_environment_block_t = nullptr;

	HeapFree(hHeapHandle, 0, process_user_parameters);

	process_user_parameters = nullptr;

	return TRUE;

FailCleanup:
	if (process_user_parameters != nullptr) HeapFree(hHeapHandle, 0, process_environment_block_t);

	if (process_user_parameters != nullptr) HeapFree(hHeapHandle, 0, process_user_parameters);

	*pImagePathBufferAddress = nullptr;

	return FALSE;
}

BOOLEAN FetchImageBaseRelocationDirectory
(
	IN     PBYTE				   pImageData,
	   OUT PIMAGE_BASE_RELOCATION *pImageBaseRelocationDirectory_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageBaseRelocationDirectory_tBaseAddress = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageData
(
	IN	   LPWSTR lpImagePath,
	IN OUT HANDLE hHeapHandle,
	   OUT PBYTE *pImageDataBaseAddress		   
)
{
	if (!lpImagePath || !hHeapHandle || !pImageDataBaseAddress) return FALSE;

	DWORD  dwFileSize  = 0,
		   dwBytesRead = 0;
	PVOID  pImageData  = nullptr;
	HANDLE hFileHandle = INVALID_HANDLE_VALUE;

	if ((hFileHandle = CreateFileW(lpImagePath, GENERIC_READ, 0, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE) return FALSE;

	if ((dwFileSize = GetFileSize(hFileHandle, nullptr)) == 0x00) return FALSE;

	if (!anonymous::CheckHeapHandle(&hHeapHandle)) return FALSE;

	if (!anonymous::CheckBuffer(dwFileSize, hHeapHandle, &pImageData)) return FALSE;

	if (!ReadFile(hFileHandle, pImageData, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) goto FailureCleanup;

	if (anonymous::CheckDataForDOSHeader(static_cast<PBYTE>(pImageData)) != 0x00) goto FailureCleanup;

	CloseHandle(hFileHandle);

	*pImageDataBaseAddress = static_cast<PBYTE>(pImageData);

	return TRUE;

FailureCleanup:
	if (hFileHandle != INVALID_HANDLE_VALUE) CloseHandle(hFileHandle);

	HeapFree(hHeapHandle, 0, pImageData);

	pImageData = NULL;

	return FALSE;
}

BOOLEAN FetchImageDosHeader
(
	IN     PBYTE			  pImageData,
	   OUT PIMAGE_DOS_HEADER *pImageDOSHeader_tBaseAddress
)
{
	if (!pImageDOSHeader_tBaseAddress || !pImageData) return FALSE;

	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

 	*pImageDOSHeader_tBaseAddress = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageData);

	return TRUE;
}

BOOLEAN FetchImageExportDirectory
(
	IN     PBYTE					pImageData,
	   OUT PIMAGE_EXPORT_DIRECTORY *pImageFileExportDirectory_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageFileExportDirectory_tBaseAddress = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageFileHeader
(
	IN     PBYTE			   pImageData,
	   OUT PIMAGE_FILE_HEADER *pImageFileHeader_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeaders = nullptr;

	if (!FetchImageNtHeaders(pImageData, &pImageNtHeaders)) return FALSE;

	*pImageFileHeader_tBaseAddress = &pImageNtHeaders->FileHeader;

	return TRUE;
}

BOOLEAN FetchImageImportDirectory
(
	IN     PBYTE					 pImageData,
	   OUT PIMAGE_IMPORT_DESCRIPTOR *pImageImportDirectory_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageImportDirectory_tBaseAddress = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageNtHeaders
(
	IN		PBYTE			   pImageData,
	   OUT	PIMAGE_NT_HEADERS *pImageNtHeaders_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS pPotentialHeaders = nullptr;
	PIMAGE_DOS_HEADER pImageDOSHeader_t = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageData);

	pPotentialHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageData + pImageDOSHeader_t->e_lfanew);

	if (pPotentialHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	*pImageNtHeaders_tBaseAddress = pPotentialHeaders;

	return TRUE;
}

BOOLEAN FetchImageOptionalHeaders
(
	IN	   PBYTE				   pImageData,
	   OUT PIMAGE_OPTIONAL_HEADER *pImageOptionalHeaders_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS	   pImageNtHeaders     = nullptr;
	PIMAGE_OPTIONAL_HEADER potential_structure = nullptr;

	if (!FetchImageNtHeaders(pImageData, &pImageNtHeaders)) return FALSE;

	potential_structure = &pImageNtHeaders->OptionalHeader;

	if (potential_structure->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return FALSE;

	*pImageOptionalHeaders_tBaseAddress = potential_structure;

	return TRUE;
}

BOOLEAN FetchImageRtFuncDirectory
(
	IN     PBYTE						  pImageData,
	   OUT PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory_tBaseAddress
)
{
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageRtFuncDirectory_tBaseAddress = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageSection
(
	IN     PBYTE 				  pImageData,
	   OUT PIMAGE_SECTION_HEADER *pImageSectionHeader_tBaseAddress
)
{
	if (!pImageData || !pImageSectionHeader_tBaseAddress) return FALSE;

	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = nullptr;

	if(!FetchImageNtHeaders(pImageData, &pImageNtHeader)) return FALSE;

	*pImageSectionHeader_tBaseAddress = reinterpret_cast <PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pImageNtHeader) + static_cast<DWORD>(sizeof(IMAGE_NT_HEADERS)));

	return TRUE;	
}

BOOLEAN FetchImageTlsDirectory
(
	IN     PBYTE				 pImageData,
	   OUT PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
)
{
	if (!pImageData || !pImageTlsDirectory_tBaseAddress) return FALSE;	
	
	if (anonymous::CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageTlsDirectory_tBaseAddress = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	return TRUE;
}

PIMAGE_SECTION_HEADER FindImageSectionHeaderByName
(
	IN			   LPCSTR				 pTagetSectionName,
	IN	  OPTIONAL PIMAGE_SECTION_HEADER pImageTextSection,
	IN	  OPTIONAL WORD					 number_of_sections,
	IN	  OPTIONAL PBYTE				 pImageData
)
{
	if ((pImageData == nullptr && pImageTextSection == nullptr) || pTagetSectionName == nullptr || pTagetSectionName[0] == 0x00 ) return nullptr;

	PIMAGE_FILE_HEADER pImageFileHeader = nullptr;

	if (number_of_sections == 0x0000)
	{
		if (pImageTextSection != nullptr)
		{
			if (strcmp(reinterpret_cast<char *>(pImageTextSection->Name), ".text") != 0)
			{
				if (pImageData == nullptr) return nullptr;

				if (FetchImageSection(pImageData, &pImageTextSection) == FALSE) return nullptr;
			}
			pImageFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(reinterpret_cast<PBYTE>(pImageTextSection) - sizeof(IMAGE_NT_HEADERS) + sizeof(DWORD));
		}
		else
		{
			if (FetchImageSection(pImageData, &pImageTextSection) == FALSE) return nullptr;

			if (FetchImageFileHeader(pImageData, &pImageFileHeader) == FALSE) return nullptr;
		}

		number_of_sections = pImageFileHeader->NumberOfSections;
	}

	PIMAGE_SECTION_HEADER pImageSectionHeader = nullptr;

	for (WORD i = 0; i < number_of_sections; i++) 
	{
		pImageSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pImageTextSection) + i * sizeof(IMAGE_SECTION_HEADER));

		if (strcmp(pTagetSectionName, reinterpret_cast<char *>(pImageSectionHeader->Name)) == 0x00) return pImageSectionHeader;
	}

	return nullptr;
}

BOOLEAN ReadStructFromProcess
(
	IN     HANDLE hTargetProcess, 
	IN     PVOID  pStructBaseAddress, 
	IN     DWORD  dwBufferSize,
	IN     HANDLE hHeapHandle,
	   OUT PVOID *pReadBufferAddress
)
{
	if (!hTargetProcess || !pStructBaseAddress ||  !dwBufferSize || !pReadBufferAddress) return FALSE;

	if(!anonymous::CheckBuffer(dwBufferSize, hHeapHandle, pReadBufferAddress)) return FALSE;

	SIZE_T	sBytesRead = 0;

	if (!ReadProcessMemory(hTargetProcess, pStructBaseAddress, *pReadBufferAddress, dwBufferSize, &sBytesRead) || sBytesRead != dwBufferSize) goto FailureCleanup;

	return TRUE;

FailureCleanup:
	HeapFree(hHeapHandle, 0, *pReadBufferAddress);

	*pReadBufferAddress = nullptr;

	return FALSE;
}