#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

#include "Printers.c"



int main(void) {
	LPWSTR pDesiredDrive = malloc(16 * sizeof(WCHAR));
 	PrintDrives(pDesiredDrive);
	LPWSTR pFilepath = malloc(MAX_PATH * sizeof(WCHAR));
	wcscpy_s(pFilepath, MAX_PATH, pDesiredDrive);
	free(pDesiredDrive);
	pFilepath = PrintSubFolders(pFilepath);
	wcscat_s(pFilepath, MAX_PATH, L"\\");
	if (CheckFolderPath(pFilepath) == FALSE) {
		exit(-3);
	}
	PrintCWD(pFilepath);
	wprintf(L"Please Enter Your Desired File Name and Format Under Your Chosen Folder: \n");
	LPWSTR pFilename = VirtualAlloc(0, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	wscanf_s(L"%64s", pFilename, MAX_PATH);
	wprintf(L"Filename's Buffer's Contetnt after wscanf_s: %s\n", pFilename);
	VirtualFree(pFilename, MAX_PATH, MEM_FREE);
	wcscat_s(pFilepath, MAX_PATH, pFilename);
	wprintf(L"Filepath Buffer's Content After calling strcat_s: %s\n", pFilepath);
	free(pFilepath);
	printf("Press 'Enter' To Exit! :)");
	return 0;
}

