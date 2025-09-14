#include "peImageParser.h"

namespace check
{

	static BOOLEAN Buffer
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

	static UCHAR DataBufferForDOSHeader
	(
		IN	  PBYTE	 pCandidateData
	)
	{
		if (pCandidateData == nullptr) return 1;

		PIMAGE_DOS_HEADER pPotentialHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pCandidateData);

		if (pPotentialHeader->e_magic != IMAGE_DOS_SIGNATURE) return 2;

		return 0;
	}

	BOOLEAN HeapHandle
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

namespace cleanUp
{
	BOOLEAN FetchPath
	(
		IN     PRTL_USER_PROCESS_PARAMETERS process_user_parameters,
		IN     HANDLE						hHeapHandle,
		IN	   PPEB							process_environment_block_t,
		IN	   LPWSTR* pImagePathBufferAddress
	)
	{
		if (process_user_parameters != nullptr) HeapFree(hHeapHandle, NULL, process_environment_block_t);

		if (process_user_parameters != nullptr) HeapFree(hHeapHandle, NULL, process_user_parameters);

		*pImagePathBufferAddress = nullptr;

		return FALSE;
	}


	PPROCESS_BASIC_INFORMATION FetchProcBasicInfo
	(
		IN    PPROCESS_BASIC_INFORMATION	 pProcessBasicInformation_t,
		IN    HANDLE						 hHeapHandle
	)
	{

		HeapFree(hHeapHandle, NULL, pProcessBasicInformation_t);

		return nullptr;
	}

}

BOOLEAN FetchPathFromRunningProcess
(
	IN     HANDLE  hTargetImageProcessHandle,
	   OUT PWSTR  *pImagePathBufferAddress
)
{
	PPEB						 pProcessEnvironmentBlock_t = nullptr;
	PRTL_USER_PROCESS_PARAMETERS process_user_parameters    = nullptr;
	BOOLEAN						 bStatus					= FALSE;
	HANDLE						 hHeapHandle				= GetProcessHeap();

	if ((hHeapHandle == INVALID_HANDLE_VALUE)) return FALSE;

	pProcessEnvironmentBlock_t = FetchRemoteProcessEnvironmentBlock(hTargetImageProcessHandle, hHeapHandle, FetchPBINtQuerySystemInformation(hTargetImageProcessHandle));

	//if (bStatus == FALSE) return cleanUp::FetchPath(process_user_parameters, hHeapHandle, pProcessEnvironmentBlock_t , pImagePathBufferAddress);

	if (check::Buffer(sizeof(RTL_USER_PROCESS_PARAMETERS), hHeapHandle, reinterpret_cast<PVOID*>(&process_user_parameters)) == FALSE)
	{
		return  cleanUp::FetchPath(process_user_parameters, hHeapHandle, pProcessEnvironmentBlock_t , pImagePathBufferAddress);
	}
	 
	if (!ReadStructFromProcess(hTargetImageProcessHandle, pProcessEnvironmentBlock_t->ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, hHeapHandle, reinterpret_cast<PVOID*>(&process_user_parameters)))
	{
		return cleanUp::FetchPath(process_user_parameters, hHeapHandle, pProcessEnvironmentBlock_t , pImagePathBufferAddress);
	}

	if (!ReadStructFromProcess(hTargetImageProcessHandle, process_user_parameters->ImagePathName.Buffer, process_user_parameters->ImagePathName.Length, hHeapHandle, reinterpret_cast<PVOID*>(pImagePathBufferAddress)))
	{
		return  cleanUp::FetchPath(process_user_parameters, hHeapHandle, pProcessEnvironmentBlock_t , pImagePathBufferAddress);
	}

	HeapFree(hHeapHandle, NULL, pProcessEnvironmentBlock_t );

	pProcessEnvironmentBlock_t  = nullptr;

	HeapFree(hHeapHandle, NULL, process_user_parameters);

	process_user_parameters = nullptr;

	return TRUE;
}

PPROCESS_BASIC_INFORMATION FetchPBINtQuerySystemInformation
(
	IN     HANDLE  hTargetImageProcessHandle
)
{
	ULONG 						 NtQueryReturnValue		    = NULL;
	fnNtQueryProcessInformation  NtQueryInformationProcess  = nullptr;
	HANDLE						 hHeapHandle				= GetProcessHeap();
	PPROCESS_BASIC_INFORMATION	 pProcessBasicInformation_t = static_cast<PPROCESS_BASIC_INFORMATION>(HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, sizeof(PROCESS_BASIC_INFORMATION)));

	if (pProcessBasicInformation_t == nullptr) return  nullptr;

	if ((NtQueryInformationProcess = reinterpret_cast<fnNtQueryProcessInformation>(GetProcessAddressReplacement(GetModuleHandleReplacement(const_cast<LPWSTR>(L"NTDLL.dll")), const_cast<LPSTR>("NtQueryInformationProcess")))) == nullptr) 
	{
		return cleanUp::FetchProcBasicInfo(pProcessBasicInformation_t, hHeapHandle);
	}

	if (NtQueryInformationProcess(hTargetImageProcessHandle, ProcessBasicInformation, pProcessBasicInformation_t, sizeof(PROCESS_BASIC_INFORMATION), &NtQueryReturnValue) != NULL)
	{
		return cleanUp::FetchProcBasicInfo(pProcessBasicInformation_t, hHeapHandle);
	}

	return pProcessBasicInformation_t;
}

PPEB FetchRemoteProcessEnvironmentBlock
(
	IN	   OPTIONAL	HANDLE					   hTargetImageProcessHandle,
	IN				HANDLE					   hHeapHandle,
	IN     OPTIONAL PPROCESS_BASIC_INFORMATION pProcessBasicInformation_t
)
{
	if (hTargetImageProcessHandle == nullptr) return nullptr;

	PPEB	pProcessEnvironmentBlock_t = nullptr;
	BOOLEAN bStatus					   = FALSE;

	check::HeapHandle(&hHeapHandle);

	if (check::Buffer(sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID*>(&pProcessEnvironmentBlock_t)) == FALSE) return FALSE;

	if (pProcessBasicInformation_t == nullptr)
	{
		if (hTargetImageProcessHandle == nullptr || hTargetImageProcessHandle == INVALID_HANDLE_VALUE) return nullptr;

		pProcessBasicInformation_t = FetchPBINtQuerySystemInformation(hTargetImageProcessHandle);

		if (pProcessBasicInformation_t == nullptr) return nullptr;
	}

	bStatus = ReadStructFromProcess(hTargetImageProcessHandle, pProcessBasicInformation_t->PebBaseAddress, sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID*>(&pProcessEnvironmentBlock_t));

	HeapFree(hHeapHandle, MEM_FREE, pProcessBasicInformation_t);

	pProcessBasicInformation_t = nullptr;

	if (bStatus == FALSE) return nullptr;

	return pProcessEnvironmentBlock_t;
}

BOOLEAN FetchImageBaseRelocationDirectory
(
	IN     PBYTE				   pImageData,
	   OUT PIMAGE_BASE_RELOCATION *pImageBaseRelocationDirectory_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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

	if ((hFileHandle   = CreateFileW(lpImagePath, GENERIC_READ, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) == INVALID_HANDLE_VALUE) return FALSE;

	if ((dwFileSize    = GetFileSize(hFileHandle, nullptr)) == NULL) return FALSE;

	if (check::HeapHandle(&hHeapHandle) == FALSE) return FALSE;

	if (check::Buffer(dwFileSize, hHeapHandle, &pImageData) == FALSE) return FALSE;

	if (!ReadFile(hFileHandle, pImageData, dwFileSize, &dwBytesRead, nullptr) || dwBytesRead != dwFileSize) goto FailureCleanup;

	if (check::DataBufferForDOSHeader(static_cast<PBYTE>(pImageData)) != NULL) goto FailureCleanup;

	CloseHandle(hFileHandle);

	*pImageDataBaseAddress = static_cast<PBYTE>(pImageData);

	return TRUE;

FailureCleanup:
	if (hFileHandle != INVALID_HANDLE_VALUE) CloseHandle(hFileHandle);

	HeapFree(hHeapHandle, 0, pImageData);

	pImageData = nullptr;

	return FALSE;
}

BOOLEAN FetchImageDosHeader
(
	IN     PBYTE			  pImageData,
	   OUT PIMAGE_DOS_HEADER *pImageDOSHeader_tBaseAddress
)
{
	if (!pImageDOSHeader_tBaseAddress || !pImageData) return FALSE;

	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

 	*pImageDOSHeader_tBaseAddress = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageData);

	return TRUE;
}

BOOLEAN FetchImageExportDirectory
(
	IN     PBYTE					pImageData,
	   OUT PIMAGE_EXPORT_DIRECTORY *pImageFileExportDirectory_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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

	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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
	
	if (check::DataBufferForDOSHeader(pImageData) != 0) return FALSE;

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

	if (number_of_sections == NULL)
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

		if (strcmp(pTagetSectionName, reinterpret_cast<char *>(pImageSectionHeader->Name)) == NULL) return pImageSectionHeader;
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

	if(check::Buffer(dwBufferSize, hHeapHandle, pReadBufferAddress) == FALSE) return FALSE;

	SIZE_T	sBytesRead = 0;

	if (!ReadProcessMemory(hTargetProcess, pStructBaseAddress, *pReadBufferAddress, dwBufferSize, &sBytesRead) || sBytesRead != dwBufferSize) goto FailureCleanup;

	return TRUE;

FailureCleanup:
	HeapFree(hHeapHandle, 0, *pReadBufferAddress);

	*pReadBufferAddress = nullptr;

	return FALSE;
}