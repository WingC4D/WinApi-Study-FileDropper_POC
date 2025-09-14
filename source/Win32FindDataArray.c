#include "Win32FindDataArray.h"

//Automates The Freeing Of The Dynamic Allocation For The Files Array Struct & All Of It's Nested Dynamic Allocations.
void FreeFileArray
(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	if (pFiles_arr_t == NULL)
	{
		return;
	}

	for (USHORT i = 0; i <= pFiles_arr_t->count - 1; i++) 
	{
		if (pFiles_arr_t->pFilesArr[i].pFileName) 
		{
			RtlSecureZeroMemory(pFiles_arr_t->pFilesArr[i].pFileName, lstrlenW(pFiles_arr_t->pFilesArr[i].pFileName) * sizeof(WCHAR));

			free(pFiles_arr_t->pFilesArr[i].pFileName);
		}
	}

	if (pFiles_arr_t->hBaseFile != INVALID_HANDLE_VALUE)
	{
		FindClose(pFiles_arr_t->hBaseFile);
	}

	free(pFiles_arr_t);
}

BOOLEAN FileBufferRoundUP
(
	PDWORD                pdwArraySize,
	PWIN32_FILE_IN_ARRAY* pFilesNames_arrAddress
)
{
	if (pdwArraySize == NULL || *pdwArraySize == 0 || pFilesNames_arrAddress == NULL || *pFilesNames_arrAddress == NULL) return FALSE;

	PWIN32_FILE_IN_ARRAY pTemp = NULL;

	if ((pdwArraySize = realloc(*pFilesNames_arrAddress, *pdwArraySize * 2 * sizeof(PWIN32_FILE_IN_ARRAY))) == NULL) return FALSE;

	*pdwArraySize = *pdwArraySize * 2;

	*pFilesNames_arrAddress = pTemp;

	return TRUE;
}

//Needs Work.
HANDLE CreateVessel
(
	LPWSTR pPath
)
{
	printf("[#] Please Enter Your Desired File Name and Format Under Your Chosen Folder!\n");//Letting The User Know What Input Is Needed.
	printf("[#] %u Characters of your Input Will Be Addmited.\n", (unsigned)(MAX_PATH - wcslen(pPath)));
	WCHAR pAnswer[MAX_PATH] = { L'\0' };
	wscanf_s(L"%259s", &pAnswer, MAX_PATH);
	unsigned iPathLength = (unsigned)wcslen(pPath);
	for (unsigned i = 259; i >= (MAX_PATH - iPathLength); i--)
	{
		printf("Index: %lu\n", i);
		pAnswer[i] = L'\0';
	}
	unsigned iAnswerLength = (unsigned)wcslen(pAnswer);
	wcscat_s(pPath, MAX_PATH, pAnswer);
	wprintf(L"Trying To Place Payload Vessel At: %s\n", pPath);

	/*
	 * Storing The Result Of The Payload Creation Attempt To A Variable Of Type HANDLE.
	 * A HANDLE Is A DWORD Value Representing The I / O Device For The Kernel.
	 * DWORD = 4 bytes. This Means There Are 2 ^ 32 | 4,294,967,296 Values To Store The Result, I.E. a number ranging from 0 -> ({2^32} - 1).
	 */

	HANDLE hFile = CreateFileW(//(Trying To Create Said Vessel.
		/*[In] */         (LPCWSTR)pPath, //{lpFileName} Casting The Program Made Path To A Long Pointer to a Constant Wide STRing &  Using It The Create The Vessel In The Dessired loaction.
		/*
		 * GENERIC_READ = 0x80000000
		 * GENERIC_WRITE = 0x40000000. (0d1073741824).
		 * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
		 */
		GENERIC_READ | GENERIC_WRITE, // {dwDesiredAccess} 0xC0000000. (0d3221225472).
		FILE_SHARE_READ, // {dwShareMode} (0d1).
		NULL, // {lpSecurity Attributes} (0d0).
		CREATE_ALWAYS, // {dwCreateDisposition} (0d2).
		FILE_ATTRIBUTE_NORMAL, //{dwFlagsAndAttributes} (0x80 || 0d128).
		NULL // {hTemplateFile} (0d0).
	);
	return hFile;
}
