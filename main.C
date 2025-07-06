#define _CRT_SECURE_NO_WARNINGS

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
	CreatePayload(pFilepath);
	Handle hFile = CreateFileW();
	free(pFilepath);
	printf("Press 'Enter' To Exit! :)");
	return 0;
}

