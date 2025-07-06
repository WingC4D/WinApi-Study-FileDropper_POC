#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include "workers.c"
#define longPathAware


#pragma comment(lib, "Shlwapi.lib")

#define _CRT_SECURE_NO_WARNINGS

int main(void) {
	LPWSTR pDesiredDrive = malloc(8 * sizeof(WCHAR));
	PrintDrives(pDesiredDrive);
	LPWSTR pFilepath = malloc(MAX_PATH * sizeof(WCHAR));
	wcscpy_s(pFilepath, MAX_PATH, pDesiredDrive);
	free(pDesiredDrive);
	pFilepath = ChooseSubDirectory(pFilepath);
	printf("reached main\n");
	wcscat_s(pFilepath, MAX_PATH, L"\\");
	PrintCWD(pFilepath);
	//strcat_s(pFilepath, MAX_PATH, pDesiredfolder);
	if (CheckFolderPath(pFilepath) == FALSE) {
		exit(-3);
	}
	PrintCWD(pFilepath);
	wprintf(L"Please Enter Your Desired File Name and Format Under Your Chosen Folder: \n");
	LPWSTR pFilename = malloc(MAX_PATH * sizeof(WCHAR));
	wscanf_s(L"%64s", pFilename, MAX_PATH);
	wprintf(L"Filename's Buffer's Contetnt after wscanf_s: %s\n", pFilename);
	LPWSTR pTemp = pFilename;
	//pFilename[wcslen(pFilename)] = L'\0';
	wcscat_s(pFilepath, MAX_PATH, pTemp);
	wprintf(L"Filename's Buffer's Contetnt after strcat_s: %s\n", pTemp);
	free(pFilename);
	wprintf(L"Filepath Buffer's Content After calling strcat_s: %s\n", pFilepath);
	free(pFilepath);
	printf("Press 'Enter' To Exit! :)");
	return 0;
}

/*

LPWSTR pFilepath = L"C:\\Users\\\0";

L"\\Desktop\\pl.C";

HANDLE hFile = INVALID_HANDLE_VALUE;

hFile = CreateFileW(pFilepath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

if (hFile == INVALID_HANDLE_VALUE) {

printf("[-] CreateFileW API Function Failed!\nError Code: %x\n", GetLastError());

return -1;

}
// printf("Please Enter Your Desired Folder Under Users: ");
//strcpy_s(pFilepath, _countof(pFilepath), "C\0");
//strcat_s(pUsername, sizeof(pUsername), "\\");
printf("[+] CreateFileW Succeeded!\nFile Handle Address: %p\n", hFile);
//strcpy_s(pFilepath, _countof(pFilepath), "C\0");
//strcat_s(pUsername, sizeof(pUsername), "\\");
*/