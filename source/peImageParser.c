#include "peImageParser.h"

BOOLEAN CheckBuffer
(
	IN     DWORD  dwSizeToAllocate,
	IN     HANDLE hHeapHandle,
	   OUT PVOID *pBufferAddress
)
{
	if (!dwSizeToAllocate || !hHeapHandle || !pBufferAddress) return FALSE;

	if (*pBufferAddress != NULL  && *pBufferAddress != UNINIT_PVOID_VALUE)
	{
		free(*pBufferAddress);

		*pBufferAddress = NULL;
	}

	*pBufferAddress = HeapAlloc(hHeapHandle, 0, dwSizeToAllocate);

	if (*pBufferAddress == NULL) return FALSE;

	return TRUE;
}

UCHAR CheckDataForDOSHeader
(
	IN	  PBYTE	 pCandidateData
)
{
	if (!*pCandidateData) return 1;

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

	*pImageDataBaseAddress = (PBYTE)pImageData;

	CloseHandle(hFileHandle);

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

BOOLEAN FetchImageTlsDirectory
(
	IN     PBYTE				 pImageData,
	   OUT PIMAGE_TLS_DIRECTORY *pImageTlsDirectory_tBaseAddress
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageTlsDirectory_tBaseAddress = (PIMAGE_TLS_DIRECTORY)(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	return TRUE;
}

BOOLEAN FetchImageRtFuncDirectory
(
	IN     PBYTE						  pImageData,
	   OUT PIMAGE_RUNTIME_FUNCTION_ENTRY *pImageRtFuncDirectory
)
{
	if (CheckDataForDOSHeader(pImageData) != 0) return FALSE;

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeaders_t = NULL;

	if (!FetchImageOptionalHeaders(pImageData, &pImageOptionalHeaders_t)) return FALSE;

	*pImageRtFuncDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pImageData + pImageOptionalHeaders_t->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	return TRUE;
}

