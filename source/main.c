#include "Printers.h"
#include "choosers.h"
#include "Externals.h"
#include "SystemInetactors.h"


int main(void) 
{
	call();
	
	WCHAR potential_drives_arr[27] = { L'\0' };
	wcscpy_s(&potential_drives_arr, 27, FetchDrives());
	if (wcslen(potential_drives_arr) == 0) 
	{
		
		printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -1;
	}
	PrintDrives(&potential_drives_arr);
	WCHAR path_arr[MAX_PATH] = { L'\0' };
	while (ChooseDrive(&path_arr, &potential_drives_arr) == FALSE) 
	{
		wprintf(L"[X] Wrong Input!\n");
		PrintDrives(&potential_drives_arr);
	}
	if (PrintSubFolders(&path_arr) == FALSE) 
	{
		printf("[X] Folder Choosing || Printing Failed!\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -2;
	}
	HANDLE hFile = CreateVessel(&path_arr);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		printf("[X] Failed To Fetch File Handle!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -3;
	}
	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}

