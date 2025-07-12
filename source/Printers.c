#include "Printers.h"
#include "choosers.h"
#include "ErrorHandlers.h"
#include "SystemInteractors.h"
// Constructing a new data type that represents HelloWorld's function pointer.
typedef void(WINAPI* HelloWorldFunctionPointer)();

void PrintMemoryError(
	LPCWSTR pCFPoint
)
{
	wprintf(L"[X] Failed To Allocate Memory For %s!\nExiting With Error Code : % x\n", pCFPoint, GetLastError());
	return;
}

void PrintDrives(
	LPWSTR pPath
) 
{
	unsigned usArrayLength = (unsigned)wcslen(pPath);
	for (unsigned i = 0; i < usArrayLength; i++) 
	{	
		wprintf(L"[#] - %c\n", pPath[i]);
	}
	return;
}

void PrintCWD(
	LPWSTR pPath
)
{
	wprintf(L"Current Working Path: %s\n", pPath);
	return;
}

BOOL PrintUserName(
	void
) 
{
	WCHAR pUsername[MAX_PATH] = { L'\0' }; //Assigning a Buffer for the current username to land at.
	DWORD pSizeofusername[8] = { NULL }; //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	if (GetUserNameW(pUsername, pSizeofusername) == 0)
	{
		return FALSE;
	}
	wprintf(L"[#] Username: %s\n", pUsername);
	RtlSecureZeroMemory(pUsername, (wcslen(pUsername) + 1));//For Fun.
	return TRUE;
}

void PrintSubFiles(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) 
{
	for(unsigned i = 0; i < pFiles_arr_t->count; i++)
	{
		wprintf(L"[%d] File Name: %s\n", i, pFiles_arr_t->pFiles_arr[i].file_data.cFileName);
	};
	return;
}
