#include "Printers.h"
#include "choosers.h"
#include "Externals.h"
#include "SystemInteractors.h"


int main(void) 
{
	call();
	WCHAR pPath[260] = { L'\0' };
	FetchDrives(pPath);
	if (pPath[0] == L'0')
	{
		printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -1;
	}
	PrintDrives(
		pPath
	);
	while (
		!UserIODrives(&pPath)
	)
	{
		wprintf(
			L"[X] Wrong Input!\n"
		);
		PrintDrives(
			pPath
		);
	}
	PrintCWD(pPath);
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t = FetchFileArrayW(&pPath);
	if (pFiles_arr_t == NULL) 
	{
		printf("[X] Folder Choosing || Printing Failed!\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -2;
	}
	PrintSubFiles(pFiles_arr_t);
	while (!UserIOFolders(pPath, pFiles_arr_t)) {
		
		pFiles_arr_t = RefetchFilesArrayW(&pPath, pFiles_arr_t);
		PrintCWD(pPath);
		if (pFiles_arr_t == NULL) {
			printf("[!] No Files Under Current Folder.\n");
			break;
		}
		PrintSubFiles(pFiles_arr_t);
	}
 	FreeFileArray(pFiles_arr_t);
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateVessel(&pPath);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		printf("[X] Failed To Fetch File Handle!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -3;
	}
	CloseHandle(hFile);
	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}

