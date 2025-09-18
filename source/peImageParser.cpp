#include "peImageParser.h"

namespace check
{
	enum class ParseStatus : UCHAR
	{
		Success = 0,
		NullInput = 1,
		InvalidDosSignature = 2
	};

	BOOLEAN HandleValidity
	(
		IN     HANDLE hCandidateHandle
	)
	{
		if (hCandidateHandle == INVALID_HANDLE_VALUE || hCandidateHandle  == nullptr) return FALSE;

		return TRUE;
	}

	BOOLEAN HeapHandle
	(
		IN OUT PHANDLE phHeapHandle
	)
	{
		if (phHeapHandle == nullptr) return FALSE;

		if (*phHeapHandle == nullptr || *phHeapHandle == INVALID_HANDLE_VALUE)
		{
			*phHeapHandle = GetProcessHeap();

			if (*phHeapHandle == INVALID_HANDLE_VALUE || *phHeapHandle == nullptr) return FALSE;
		}
		return TRUE;
	}

	BOOLEAN Buffer
	(
		IN     DWORD  dwSizeToAllocate,
		IN     HANDLE hHeapHandle,
		   OUT PVOID *pBufferAddress
	)
	{
		if (dwSizeToAllocate == NULL|| pBufferAddress == nullptr) return FALSE;

		if (*pBufferAddress != UNINIT_PVOID_VALUE && *pBufferAddress != nullptr) return TRUE;

		HeapHandle(&hHeapHandle);

		*pBufferAddress = HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, dwSizeToAllocate);

		if (*pBufferAddress == nullptr) return FALSE;

		return TRUE;
	}

	ParseStatus DataBufferForDOSHeader
	(
		IN	   PBYTE	 pCandidateData
	)
	{
		if (pCandidateData == nullptr) return ParseStatus::NullInput;

		PIMAGE_DOS_HEADER pPotentialHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pCandidateData);

		if (pPotentialHeader->e_magic != IMAGE_DOS_SIGNATURE) return ParseStatus::InvalidDosSignature;

		return ParseStatus::Success;
	}
}

namespace cleanUp
{
	PPROCESS_BASIC_INFORMATION FetchProcBasicInfo
	(
		IN     PPROCESS_BASIC_INFORMATION *pProcessBasicInformation_t,
		IN     HANDLE					   hHeapHandle
	)
	{
		*pProcessBasicInformation_t = nullptr;

		return nullptr;
	}

	PBYTE FetchImageData
	(
		IN     LPVOID *pImageData,
		IN     HANDLE  hHeapHandle
	)
	{
		check::HeapHandle(&hHeapHandle);

		HeapFree(hHeapHandle, NULL, *pImageData);

		*pImageData = nullptr;

		return nullptr;
	}

	BOOLEAN ReadStructFromProcess
	(
		IN     LPVOID *pReadBufferAddress,
		IN     HANDLE  hHeapHandle
	)
	{
		check::HeapHandle(&hHeapHandle);

		HeapFree(hHeapHandle, NULL, *pReadBufferAddress);

		*pReadBufferAddress = nullptr;

		return FALSE;
	}
}

PeFile::PeFile()
{
	bDidIAllocate			 = FALSE;
	pBaseOfData				 = nullptr;
	hHeapHandle				 = GetProcessHeap();
	pImageDosHeader			 = nullptr;
	pImageNtHeader			 = nullptr;
	pImageFileHeader		 = nullptr;
	pImageOptionalHeaders	 = nullptr;
	pImageFirstSectionHeader = nullptr;
	pImageRunTimeFunction	 = nullptr;
	pImageImportAddressTable	 = nullptr;
	pImageTlsDirectory		 = nullptr;
	pImageDosHeader			 = nullptr;
	pImageNtHeader			 = nullptr;
	return;
}

PeFile::~PeFile()
{
	if (this->bDidIAllocate == TRUE)
	{
		HeapFree(this->hHeapHandle, NULL, this->pBaseOfData);
	}

	pBaseOfData				 = nullptr;
	pImageDosHeader			 = nullptr;
	pImageNtHeader			 = nullptr;
	pImageFileHeader		 = nullptr;
	pImageOptionalHeaders	 = nullptr;
	pImageFirstSectionHeader = nullptr;
	pImageRunTimeFunction	 = nullptr;
	pImageImportAddressTable	 = nullptr;
	pImageTlsDirectory		 = nullptr;
	pImageDosHeader			 = nullptr;
	pImageNtHeader			 = nullptr;

}

void PeFile::ConsumeDataStream(PBYTE pCandidateData)
{

	

	return;
}

 error_codes PeFile::ParseDataFilePath(::LPWSTR lpFilePath)
{
	HANDLE		hFileHandle		   = INVALID_HANDLE_VALUE,
				hHeapHandle		   = INVALID_HANDLE_VALUE;
	DWORD		dwFileSize		   = NULL,
				dwBytesRead		   = NULL;
	PBYTE		pCandidateFileData = nullptr;
	error_codes ecStatus		   = Success;

	hFileHandle  = CreateFileW(lpFilePath, GENERIC_READ, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (CheckHandleValidity(hFileHandle) == FALSE)
	{
		return InvalidHandle;
	}
	
	dwFileSize = GetFileSize(hFileHandle, nullptr);

	if (dwFileSize == NULL) return FileSizeIsZero;

	hHeapHandle = GetProcessHeap();

	if (CheckHandleValidity(hHeapHandle) == FALSE)
	{
		return InvalidHandle;
	}

	pCandidateFileData = static_cast<PBYTE>(HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, dwFileSize));

	if (pCandidateFileData == nullptr) return FailedToAllocateMemory;

	this->bDidIAllocate = TRUE;

	if (ReadFile(hFileHandle, pCandidateFileData, dwFileSize, &dwBytesRead, nullptr) == FALSE)
	{
		HeapFree(hHeapHandle, NULL, pCandidateFileData);

		return FailedToReadFile;
	}

	if (CheckCandidateDataValidity(pCandidateFileData) != Success)
	{
		if (HeapFree(hHeapHandle, NULL, pCandidateFileData) == FALSE) return InvalidBufferSize;

	}

	this->hHeapHandle	  = hHeapHandle;

	return MapFileStructures(pCandidateFileData, TRUE);
}

LPWSTR FetchImagePathFromRemoteProcess
(
	IN				HANDLE	 hTargetProcessHandle
)
{
	PRTL_USER_PROCESS_PARAMETERS pUserProcessParameters = nullptr;
	HANDLE						 hHeapHandle			= GetProcessHeap();
	BOOLEAN						 bStatus				= FALSE;
	LPWSTR						 pImagePath				= nullptr;
	PPEB						 pProcEnvironmentBlock  = nullptr;

	if (check::HandleValidity(hHeapHandle) == FALSE) return FALSE;

	pProcEnvironmentBlock = FetchRemoteProcessEnvironmentBlock(hTargetProcessHandle, hHeapHandle, nullptr);

	if (pProcEnvironmentBlock == nullptr) return  nullptr;

	pUserProcessParameters = FetchRemoteRTLUserProcessParameters(hTargetProcessHandle, hHeapHandle, pProcEnvironmentBlock);

	HeapFree(hHeapHandle, NULL, pProcEnvironmentBlock);

	pProcEnvironmentBlock = nullptr;

	if (pUserProcessParameters == nullptr) return FALSE;

	if (check::Buffer(pUserProcessParameters->ImagePathName.Length, hHeapHandle, reinterpret_cast<PVOID *>(&pImagePath)) == FALSE) return FALSE;

	bStatus = ReadStructFromProcess(hTargetProcessHandle, pUserProcessParameters->ImagePathName.Buffer, pUserProcessParameters->ImagePathName.Length, hHeapHandle, reinterpret_cast<PVOID *>(&pImagePath));

	HeapFree(hHeapHandle, NULL, pUserProcessParameters);

	pUserProcessParameters = nullptr;

	if (bStatus == FALSE) return nullptr;

	return pImagePath;
}

PPROCESS_BASIC_INFORMATION FetchRemotePBINtQuerySystemInformation
(
	IN				HANDLE hTargetImageProcessHandle,
	IN     OPTIONAL HANDLE hHeapHandle
)
{
	if (check::HeapHandle(&hHeapHandle) == FALSE) return nullptr;

	ULONG 						 NtQueryReturnValue		    = NULL;
	fnNtQueryProcessInformation  NtQueryInformationProcess  = nullptr;
	PPROCESS_BASIC_INFORMATION	 pProcessBasicInformation_t = static_cast<PPROCESS_BASIC_INFORMATION>(HeapAlloc(hHeapHandle, HEAP_ZERO_MEMORY, sizeof(PROCESS_BASIC_INFORMATION)));

	if (pProcessBasicInformation_t == nullptr) return nullptr;

	if ((NtQueryInformationProcess = reinterpret_cast<fnNtQueryProcessInformation>(GetProcessAddressReplacement(GetModuleHandleReplacement(L"NTDLL.dll"), const_cast<LPSTR>("NtQueryInformationProcess")))) == nullptr) 
	{
		return cleanUp::FetchProcBasicInfo(&pProcessBasicInformation_t, hHeapHandle);
	}

	if (NtQueryInformationProcess(hTargetImageProcessHandle, ProcessBasicInformation, pProcessBasicInformation_t, sizeof(PROCESS_BASIC_INFORMATION), &NtQueryReturnValue) < NULL)
	{
		return cleanUp::FetchProcBasicInfo(&pProcessBasicInformation_t, hHeapHandle);
	}

	return pProcessBasicInformation_t;
}

PPEB FetchRemoteProcessEnvironmentBlock
(
	IN				HANDLE					   hTargetImageProcessHandle,
	IN				HANDLE					   hHeapHandle,
	IN     OPTIONAL PPROCESS_BASIC_INFORMATION pProcessBasicInformation_t
)
{
	if (check::HandleValidity(hTargetImageProcessHandle) == FALSE) return nullptr;

	PPEB	pProcessEnvironmentBlock_t = nullptr;
	BOOLEAN bStatus					   = FALSE;

	if (check::Buffer(sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID *>(&pProcessEnvironmentBlock_t)) == FALSE || check::HeapHandle(&hHeapHandle) == FALSE)
	{
		return nullptr;
	}

	if (pProcessBasicInformation_t == nullptr)
	{
		pProcessBasicInformation_t = FetchRemotePBINtQuerySystemInformation(hTargetImageProcessHandle, hHeapHandle);

		if (pProcessBasicInformation_t == nullptr) return nullptr;
	}

	bStatus = ReadStructFromProcess(hTargetImageProcessHandle, pProcessBasicInformation_t->PebBaseAddress, sizeof(PEB), hHeapHandle, reinterpret_cast<PVOID*>(&pProcessEnvironmentBlock_t));

	HeapFree(hHeapHandle, NULL, pProcessBasicInformation_t);

	pProcessBasicInformation_t = nullptr;

	if (bStatus == FALSE) return nullptr;

	return pProcessEnvironmentBlock_t;
}

PRTL_USER_PROCESS_PARAMETERS FetchRemoteRTLUserProcessParameters
(
	IN				HANDLE hTargetImageProcessHandle,
	IN				HANDLE hHeapHandle,
	IN     OPTIONAL PPEB   pProcessEnvironmentBlock_t
)
{
	if (check::HandleValidity(hTargetImageProcessHandle) == FALSE) return nullptr;

	PRTL_USER_PROCESS_PARAMETERS pRTLUserProcessParameters_t = nullptr;
	BOOLEAN						 bStatus1					 = FALSE,
								 bStatus2					 = FALSE;

	if (check::HeapHandle(&hHeapHandle) == FALSE) return nullptr;

	if (pProcessEnvironmentBlock_t == nullptr)
	{
		bStatus1 = TRUE;

		pProcessEnvironmentBlock_t = FetchRemoteProcessEnvironmentBlock(hTargetImageProcessHandle, hHeapHandle, FetchRemotePBINtQuerySystemInformation(hTargetImageProcessHandle, hHeapHandle));

		if (pProcessEnvironmentBlock_t == nullptr) return nullptr;
	}

	if (check::Buffer(sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, hHeapHandle, reinterpret_cast<PVOID *>(&pRTLUserProcessParameters_t)) == FALSE) return nullptr;

	bStatus2 = ReadStructFromProcess(hTargetImageProcessHandle, pProcessEnvironmentBlock_t->ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, hHeapHandle, reinterpret_cast<PVOID*>(&pRTLUserProcessParameters_t));

	if (bStatus1 == TRUE) 
	{
		HeapFree(hHeapHandle, NULL, pProcessEnvironmentBlock_t);

		pProcessEnvironmentBlock_t = nullptr;
	}

	if (bStatus2 == FALSE) return nullptr;

	return pRTLUserProcessParameters_t;
}

BOOLEAN FetchImageBaseRelocationDirectory
(
	IN				PBYTE				    pImageData,
	   OUT			PIMAGE_BASE_RELOCATION *pImageBaseRelocationDirectory_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t) == FALSE) return FALSE;

	*pImageBaseRelocationDirectory_tBaseAddress = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	return TRUE;
}

PBYTE FetchImageData
(
	IN				LPWSTR lpImagePath,
	IN     OPTIONAL	HANDLE hHeapHandle,
	   OUT OPTIONAL PDWORD pdwImageSize
)
{
	if (lpImagePath == nullptr) return FALSE;

	if (lpImagePath[0] == NULL)	   return FALSE;

	DWORD  dwBytesRead = NULL;
	LPVOID pImageData  = nullptr;
	HANDLE hFileHandle = INVALID_HANDLE_VALUE;
	

	hFileHandle = CreateFileW(lpImagePath, GENERIC_READ, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (check::HandleValidity(hFileHandle) == FALSE) return FALSE;

	*pdwImageSize = GetFileSize(hFileHandle, nullptr);

	if (*pdwImageSize == NULL) return FALSE;

	if (check::HeapHandle(&hHeapHandle)	== FALSE) return FALSE;

	if (check::Buffer(*pdwImageSize, hHeapHandle, &pImageData)	== FALSE) return FALSE;
	
	if (ReadFile(hFileHandle, pImageData, *pdwImageSize, &dwBytesRead, nullptr) == FALSE || dwBytesRead != *pdwImageSize)
	{
		return cleanUp::FetchImageData(&pImageData, hHeapHandle);
	}

	if (check::DataBufferForDOSHeader(static_cast<PBYTE>(pImageData)) != check::ParseStatus::Success)
	{
		return cleanUp::FetchImageData(&pImageData, hHeapHandle);
	}

	CloseHandle(hFileHandle);

	return static_cast <PBYTE>(pImageData);
}

BOOLEAN FetchImageDosHeader
(
	IN				PBYTE			   pImageData,
	   OUT			PIMAGE_DOS_HEADER *pImageDOSHeader_tBaseAddress
)
{
	if (!pImageDOSHeader_tBaseAddress || !pImageData) return FALSE;

	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

 	*pImageDOSHeader_tBaseAddress = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageData);

	return TRUE;
}

BOOLEAN FetchImageExportDirectory
(
	IN				PBYTE					 pImageData,
	   OUT			PIMAGE_EXPORT_DIRECTORY *pImageFileExportDirectory_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageFileExportDirectory_tBaseAddress = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageFileHeader
(
	IN				PBYTE			    pImageData,
	   OUT			PIMAGE_FILE_HEADER *pImageFileHeader_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeaders = nullptr;

	if (FetchImageNtHeaders(pImageData, &pImageNtHeaders) == FALSE) return FALSE;

	*pImageFileHeader_tBaseAddress = &pImageNtHeaders->FileHeader;

	return TRUE;
}

BOOLEAN FetchImageImportDirectory
(
	IN				PBYTE					  pImageData,
	   OUT			PIMAGE_IMPORT_DESCRIPTOR *pImageImportDirectory_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageImportDirectory_tBaseAddress = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageNtHeaders
(
	IN				PBYTE			   pImageData,
	   OUT			PIMAGE_NT_HEADERS *pImageNtHeaders_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_NT_HEADERS pPotentialHeaders = nullptr;
	PIMAGE_DOS_HEADER pImageDOSHeader_t = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageData);

	pPotentialHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageData + pImageDOSHeader_t->e_lfanew);

	if (pPotentialHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	*pImageNtHeaders_tBaseAddress = pPotentialHeaders;

	return TRUE;
}

BOOLEAN FetchImageOptionalHeaders
(
	IN				PBYTE				    pImageData,
	   OUT			PIMAGE_OPTIONAL_HEADER *pImageOptionalHeaders_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_NT_HEADERS	   pImageNtHeaders      = nullptr;
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = nullptr;

	if (FetchImageNtHeaders(pImageData, &pImageNtHeaders) == FALSE) return FALSE;

	pImageOptionalHeader = &pImageNtHeaders->OptionalHeader;

	if (pImageOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return FALSE;

	*pImageOptionalHeaders_tBaseAddress = pImageOptionalHeader;

	return TRUE;
}

BOOLEAN FetchImageRtFuncDirectory
(
	IN				PBYTE						   pImageData,
	   OUT			PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory_tBaseAddress
)
{
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t) == FALSE) return FALSE;

	*pImageRtFuncDirectory_tBaseAddress = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageSection
(
	IN				PBYTE 				   pImageData,
	   OUT			PIMAGE_SECTION_HEADER *pImageSectionHeader_tBaseAddress
)
{
	if (pImageData == nullptr|| pImageSectionHeader_tBaseAddress == nullptr) return FALSE;

	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_SECTION_HEADER pImageTextSectionHeader	= nullptr;
	PIMAGE_NT_HEADERS	  pImageNtHeader			= nullptr;
	DWORD				  dwImageNtHeaderSize		= NULL;
	PBYTE				  pImageNtHeaderBaseAddress = nullptr;

	dwImageNtHeaderSize = sizeof(IMAGE_NT_HEADERS);

	if (dwImageNtHeaderSize == NULL) return FALSE;

	if(FetchImageNtHeaders(pImageData, &pImageNtHeader) == FALSE) return FALSE;

	pImageNtHeaderBaseAddress = reinterpret_cast<PBYTE>(pImageNtHeader);

	pImageTextSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(pImageNtHeaderBaseAddress + dwImageNtHeaderSize);

	*pImageSectionHeader_tBaseAddress = pImageTextSectionHeader;

	return TRUE;	
}

BOOLEAN FetchImageTlsDirectory
(
	IN				PBYTE				  pImageData,
	   OUT			PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
)
{
	if (pImageData == nullptr || pImageTlsDirectory_tBaseAddress == nullptr) return FALSE;
	
	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = nullptr;

	if (FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t) == FALSE) return FALSE;

	*pImageTlsDirectory_tBaseAddress = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	return TRUE;
}

PIMAGE_SECTION_HEADER FindImageSectionHeaderByName
(
	IN				LPCSTR				 pTagetSectionName,
	IN				PBYTE				 pImageData
)
{
	if (pImageData == nullptr || pTagetSectionName == nullptr) return nullptr;

	if (pTagetSectionName[0] == NULL) return nullptr;

	if (check::DataBufferForDOSHeader(pImageData) != check::ParseStatus::Success) return nullptr;

	PIMAGE_FILE_HEADER	  pImageFileHeader		    = nullptr;
	PIMAGE_SECTION_HEADER pImageSectionHeader	    = nullptr;
	PBYTE				  pImageSectionsBaseAddress = nullptr;
	PCHAR				  pImageSectionName			= nullptr;


	if (FetchImageFileHeader(pImageData, &pImageFileHeader) == FALSE) return nullptr;

	if (FetchImageSection(pImageData, &pImageSectionHeader) == FALSE) return nullptr;

	if (strcmp(pTagetSectionName, TextSection) == 0) return pImageSectionHeader;

	pImageSectionsBaseAddress = reinterpret_cast<PBYTE>(pImageSectionHeader);

	for (WORD i = 1; i < pImageFileHeader->NumberOfSections; i++) 
	{
		pImageSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(pImageSectionsBaseAddress + i * sizeof(IMAGE_SECTION_HEADER));

		pImageSectionName = reinterpret_cast<PCHAR>(pImageSectionHeader->Name);

		if (strcmp(pTagetSectionName, pImageSectionName) == 0) return pImageSectionHeader;
	}

	return nullptr;
}

BOOLEAN ReadStructFromProcess
(
	IN				HANDLE hTargetProcess, 
	IN				PVOID  pStructBaseAddress, 
	IN				DWORD  dwBufferSize,
	IN				HANDLE hHeapHandle,
	   OUT			PVOID *pReadBufferAddress
)
{
	if (hTargetProcess == nullptr || hTargetProcess == INVALID_HANDLE_VALUE || pStructBaseAddress == nullptr || dwBufferSize  == NULL || pReadBufferAddress == nullptr) return FALSE;

	if (check::HeapHandle(&hHeapHandle) == FALSE) return FALSE;

	if (check::Buffer(dwBufferSize, hHeapHandle, pReadBufferAddress) == FALSE) return FALSE;

	SIZE_T sBytesRead = 0;

	if (ReadProcessMemory(hTargetProcess, pStructBaseAddress, *pReadBufferAddress, dwBufferSize, &sBytesRead) == FALSE || sBytesRead != dwBufferSize) return cleanUp::ReadStructFromProcess(pReadBufferAddress, hHeapHandle);

	return TRUE;
}