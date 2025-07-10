#include "Printers.h"
#include "choosers.h"
#include "Externals.h"
#include "SystemInteractors.h"


int main(void) 
{
	call();
	LPWSTR pPath[MAX_PATH] = {L'\0'};
	FetchDrives(pPath);
	if (pPath[0] == L'0')
	{
		printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -1;
	}
	PrintDrives(pPath);
	BOOL result = UserIODrives(pPath);
	while (result == FALSE)
	{
		wprintf(L"[X] Wrong Input!\n");
		PrintDrives(pPath);
		result = UserIODrives(pPath);
	}
	if (PrintSubFolders(pPath) == FALSE) 
	{
		printf("[X] Folder Choosing || Printing Failed!\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -2;
	}
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateVessel(pPath);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		printf("[X] Failed To Fetch File Handle!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -3;
	}
	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}

