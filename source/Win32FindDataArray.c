#include "Win32FindDataArray.h"

//Automates Taking All System-Available Drive Letter And putting Them To A Path Buffer.
BOOL FetchDrives(
	LPWSTR pPath
)
{
	DWORD dwDrivesBitMask = GetLogicalDrives();
	
	if (dwDrivesBitMask == 0) return FALSE;

	WCHAR base_wchar = L'A';

	unsigned drives_index = 0;
	
	for (WCHAR loop_index = 0; loop_index <= 26; loop_index++)
	{
		if (dwDrivesBitMask & (1 << loop_index)) {
			pPath[drives_index] = base_wchar + loop_index;
			drives_index++;
		}
	}
	pPath[drives_index] = L'\0';
	return TRUE;
}

/*
 * Shortens and Automates The Fetching of Files Under A Working Path, Using Only, Said Path .
 * Returing All The Files In An Struct Holding The Array For Easier Further Manipulation. 
 */
LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW(
	LPWSTR pPath
)
{
	//Initilizing Data Needed.
	;
	
	WIN32_FIND_DATAW find_data_t;
	
	size_t sArraySize = 3;

	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t = (WIN32_FIND_DATA_ARRAYW *)malloc(sArraySize * sizeof(WIN32_FIND_DATA_ARRAYW));
	
	pFiles_arr_t->hBaseFile = INVALID_HANDLE_VALUE;
	
	pFiles_arr_t->pFiles_arr = (LPWIN32_FILE_IN_ARRAY)calloc(sArraySize, sizeof(WIN32_FILE_IN_ARRAY));
	
	if (pFiles_arr_t->pFiles_arr == NULL) return NULL;
	
	wcscat_s(pPath, MAX_PATH, L"*");

	pFiles_arr_t->hBaseFile = FindFirstFileW(pPath, &find_data_t);

	if (pFiles_arr_t->hBaseFile == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
	
	pPath[wcslen(pPath) - 1] = L'\0';

	unsigned i = 0;
	
	//recursive file retrival.
	while (FindNextFileW(pFiles_arr_t->hBaseFile, &find_data_t)) 
	{	
		pFiles_arr_t->pFiles_arr[i].file_data = find_data_t;
		
		pFiles_arr_t->pFiles_arr[i].index = i;
		
		if (i == sArraySize / 2) 
		{
			if (FileBufferRoundUP(&sArraySize, &pFiles_arr_t->pFiles_arr) == FALSE) return NULL;	
		}
		i++;
	}
	
	pFiles_arr_t->count = i;
	
	pFiles_arr_t->highest_order_of_magnitude = floor(log10(i));
	
	return pFiles_arr_t;
}

//Automates The Freeing Of The Dynamic Allocation For The Files Array Struct & All Of It's Nested Dynamic Allocations.
void FreeFileArray(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	FindClose(pFiles_arr_t->hBaseFile);
	free(pFiles_arr_t->pFiles_arr);
	free(pFiles_arr_t);
	return;
}

LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) 
{
	FreeFileArray(pFiles_arr_t);
	return FetchFileArrayW(pPath);
}

//Handles Dynamic Small (RN Not As Possible) Memory Allocation For The Creation Of The Files Array Struct.
BOOL FileBufferRoundUP(
	size_t *psArray,
	LPWIN32_FIND_DATAW* pFiles_arr
)
{
	*psArray = *psArray * 2;
	LPWIN32_FIND_DATAW pTemp = (LPWIN32_FIND_DATAW)realloc(*pFiles_arr, *psArray * sizeof(WIN32_FIND_DATAW));
	if (pTemp == NULL) return FALSE;
	*pFiles_arr = pTemp;
	return TRUE;
}

//Needs Work.
HANDLE CreateVessel(
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
