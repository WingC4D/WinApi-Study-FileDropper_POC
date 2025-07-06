

#include <Windows.h>
#include <stdio.h>

#include "Printers.c"

int main(void) {
	LPWSTR pFilepath = malloc(MAX_PATH * sizeof(WCHAR));
	PrintDrives(pFilepath);
	PrintSubFolders(pFilepath);
	if (!CheckFolderPath(pFilepath)) {
		exit(-3);
	}
	HANDLE hFile = CreatePayload(pFilepath);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		printf("Failed To Create The Payload! :(\nExiting With Error Code: %x\n", GetLastError());
		return -5;
	}
	printf("Payload Created Successfully! :)\n");
	printf("Press 'Enter' To Exit! :)");
	return 0;
}

