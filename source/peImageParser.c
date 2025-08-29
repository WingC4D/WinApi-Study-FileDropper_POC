#include "../Headers/peImageParser.h"

BOOLEAN CheckBuffer
(
	IN     DWORD  dwSizeToAllocate,
	IN     HANDLE hHeapHandle,
	   OUT PVOID *pBufferAddress
)
{
	if (!dwSizeToAllocate || !hHeapHandle || !pBufferAddress) return FALSE;

	if (*pBufferAddress != NULL && *pBufferAddress != UNINIT_PVOID_VALUE && *pBufferAddress != 0) return TRUE;

	*pBufferAddress = HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, dwSizeToAllocate);

	if (*pBufferAddress == NULL) return FALSE;

	return TRUE;
}

UCHAR CheckDataForDOSHeader
(
	IN	  PBYTE	 pCandidateData
)
{
	if (pCandidateData == NULL) return FALSE;

	PIMAGE_DOS_HEADER pPotentialHeader = (PIMAGE_DOS_HEADER)pCandidateData;

	if (pPotentialHeader->e_magic != IMAGE_DOS_SIGNATURE) return 2;

	return 0;
}

BOOLEAN CheckHeapHandle
(
	IN OUT PHANDLE phHeapHandle
)
{
	if (!phHeapHandle) return FALSE;

	if (*phHeapHandle == NULL || *phHeapHandle == INVALID_HANDLE_VALUE || *phHeapHandle == 0)
		
		if ((*phHeapHandle = GetProcessHeap()) == INVALID_HANDLE_VALUE) return FALSE;

	return TRUE;
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
	PROCESS_BASIC_INFORMATION	 process_basic_info_t		 = { 0 };
	HANDLE						 hHeapHandle			 	 = INVALID_HANDLE_VALUE;

	if ((hHeapHandle = GetProcessHeap()) == INVALID_HANDLE_VALUE) return FALSE;
		
	if ((NtQueryInformationProcess = (fnNtQueryProcessInformation)GetProcAddress(GetModuleHandleW(L"NTDLL.dll"), "NtQueryInformationProcess")) == NULL) return FALSE;

	NtQueryInformationProcess(hTargetImageProcessHandle, ProcessBasicInformation, &process_basic_info_t, sizeof(PROCESS_BASIC_INFORMATION), &NtQueryReturnValue);

	if (!CheckBuffer(sizeof(PEB), hHeapHandle, (PVOID*)&process_environment_block_t)) return FALSE;

	if (!ReadStructFromProcess(hTargetImageProcessHandle, process_basic_info_t.PebBaseAddress, sizeof(PEB), hHeapHandle, (PVOID *)&process_environment_block_t)) goto FailCleanup;

	if (!CheckBuffer(sizeof(PEB), hHeapHandle, (PVOID*)&process_user_parameters)) return FALSE;

	if (!ReadStructFromProcess(hTargetImageProcessHandle, process_environment_block_t->ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, hHeapHandle, (PVOID*)&process_user_parameters)) goto FailCleanup;

	if (!ReadStructFromProcess(
		hTargetImageProcessHandle,
		process_user_parameters->ImagePathName.Buffer,
		process_user_parameters->ImagePathName.Length,
		hHeapHandle,
		(PVOID*)pImagePathBufferAddress
	)) return FALSE;

	HeapFree(hHeapHandle, 0, process_environment_block_t);

	process_environment_block_t = NULL;

	HeapFree(hHeapHandle, 0, process_user_parameters);

	process_user_parameters = NULL;

	return TRUE;

FailCleanup:
	if (process_user_parameters != NULL) HeapFree(hHeapHandle, 0, process_environment_block_t);

	if (process_user_parameters != NULL) HeapFree(hHeapHandle, 0, process_user_parameters);

	*pImagePathBufferAddress = NULL;

	return FALSE;
}

BOOLEAN FetchImageBaseRelocDirectory
(
	IN     PBYTE				   pImageData,
	   OUT PIMAGE_BASE_RELOCATION *pImageBaseRelocDirectory_tBaseAddress
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageBaseRelocDirectory_tBaseAddress = (PIMAGE_BASE_RELOCATION)(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

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
	PVOID  pImageData  = NULL;
	HANDLE hFileHandle = INVALID_HANDLE_VALUE;

	if ((hFileHandle = CreateFileW(lpImagePath, GENERIC_READ, 0, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE) return FALSE;

	if ((dwFileSize = GetFileSize(hFileHandle, NULL)) == 0) return FALSE;

	if (!CheckHeapHandle(&hHeapHandle)) return FALSE;

	if (!CheckBuffer(dwFileSize, hHeapHandle, &pImageData)) return FALSE;

	if (!ReadFile(hFileHandle, pImageData, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) goto FailureCleanup;

	if (CheckDataForDOSHeader((PBYTE)pImageData) != 0) goto FailureCleanup;

	CloseHandle(hFileHandle);

	*pImageDataBaseAddress = (PBYTE)pImageData;

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

	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

 	*pImageDOSHeader_tBaseAddress = (PIMAGE_DOS_HEADER)pImageData;

	return TRUE;
}

BOOLEAN FetchImageExportDirectory
(
	IN     PBYTE					pImageData,
	   OUT PIMAGE_EXPORT_DIRECTORY *pImageFileExportDirectory_tBaseAddress
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageFileExportDirectory_tBaseAddress = (PIMAGE_EXPORT_DIRECTORY)(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageFileHeader
(
	IN     PBYTE			   pImageData,
	   OUT PIMAGE_FILE_HEADER *pImageFileHeader_tBaseAddress
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeaders	  = NULL;

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
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageImportDirectory_tBaseAddress = (PIMAGE_IMPORT_DESCRIPTOR)(pImageData+ pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageNtHeaders
(
	IN		PBYTE			   pImageData,
	   OUT	PIMAGE_NT_HEADERS *pImageNtHeaders_tBaseAddress
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS pPotentialHeaders = NULL;
	PIMAGE_DOS_HEADER pImageDOSHeader_t = (PIMAGE_DOS_HEADER)pImageData;

	pPotentialHeaders = (PIMAGE_NT_HEADERS)(pImageData + pImageDOSHeader_t->e_lfanew);

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
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS	  pImageNtHeaders     = NULL;
	IMAGE_OPTIONAL_HEADER potential_structure = { 0 };

	if (!FetchImageNtHeaders(pImageData, &pImageNtHeaders)) return FALSE;

	potential_structure = pImageNtHeaders->OptionalHeader;

	if (potential_structure.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return FALSE;

	*pImageOptionalHeaders_tBaseAddress = &potential_structure;

	return TRUE;
}

BOOLEAN FetchImageRtFuncDirectory
(
	IN     PBYTE						  pImageData,
	   OUT PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory_tBaseAddress
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageRtFuncDirectory_tBaseAddress = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageSection
(
	IN     PBYTE 				  pImageData,
	   OUT PIMAGE_SECTION_HEADER *pImageSectionHeader_tBaseAddress
)
{
	if (!pImageData || !pImageSectionHeader_tBaseAddress) return FALSE;
 	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = NULL;

	if(!FetchImageNtHeaders(pImageData, &pImageNtHeader)) return FALSE;

	*pImageSectionHeader_tBaseAddress = (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeader + (DWORD)sizeof(IMAGE_NT_HEADERS));

	return TRUE;	
}

BOOLEAN FetchImageTlsDirectory
(
	IN     PBYTE				 pImageData,
	   OUT PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
)
{
	if (!pImageData || !pImageTlsDirectory_tBaseAddress) return FALSE;	
	
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageTlsDirectory_tBaseAddress = (PIMAGE_TLS_DIRECTORY)(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	return TRUE;
}

PIMAGE_SECTION_HEADER FindImageSectionHeaderByName
(
	IN			   LPSTR				 pTagetSectionName,
	IN	  OPTIONAL PIMAGE_SECTION_HEADER pImageTextSection,
	IN	  OPTIONAL WORD					 number_of_sections,
	IN	  OPTIONAL PBYTE				 pImageData

)
{
	if ((pImageData == NULL && pImageTextSection == NULL) || 
		pTagetSectionName == NULL || 
		pTagetSectionName[0] == 0x0) return NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	if (number_of_sections == 0)
	{
		if (pImageTextSection != NULL)
		{
			if (strcmp((char*)pImageTextSection->Name, ".text") != 0)
			{
				if (pImageData == NULL) return NULL;

				if (FetchImageSection(pImageData, &pImageTextSection) == FALSE) return NULL;
			}

			pImageFileHeader = (PIMAGE_FILE_HEADER)((PBYTE)pImageTextSection - sizeof(IMAGE_NT_HEADERS) + sizeof(DWORD));
			
		} else
		{

			if (FetchImageSection(pImageData, &pImageTextSection) == FALSE) return NULL;

			if (FetchImageFileHeader(pImageData, &pImageFileHeader) == FALSE) return NULL;
		}
		number_of_sections = pImageFileHeader->NumberOfSections;
	}
	PIMAGE_SECTION_HEADER pImageSectionHeader = NULL;

	for (WORD i = 0; i < number_of_sections; i++) 
	{
		pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageTextSection + i * sizeof(IMAGE_SECTION_HEADER));

		if (strcmp(pTagetSectionName, (char *)pImageSectionHeader->Name) == 0x0) return pImageSectionHeader;
	}
		return NULL;
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

	if(!CheckBuffer(dwBufferSize, hHeapHandle, pReadBufferAddress)) return FALSE;

	SIZE_T	sBytesRead = 0;

	if (!ReadProcessMemory(hTargetProcess, pStructBaseAddress, *pReadBufferAddress, dwBufferSize, &sBytesRead) || sBytesRead != dwBufferSize) goto FailureCleanup;

	return TRUE;

FailureCleanup:
	HeapFree(hHeapHandle, 0, *pReadBufferAddress);

	*pReadBufferAddress = NULL;

	return FALSE;
}