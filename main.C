#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include "workers.c"

#pragma comment(lib, "Shlwapi.lib")

#define _CRT_SECURE_NO_WARNINGS

int main(void) {
	//PrintUserName();
	char pFilepath[512];
	char pDesiredfolder[96];
	char pFilename[256];
	CHAR pDesiredDrive[4];
	PrintDrives(pDesiredDrive);
	printf("Contents in main.C: %s\n", pDesiredDrive);
	strcpy_s(pFilepath, (unsigned int)_countof(pFilepath), pDesiredDrive);
	printf("Please Choose a Folder under the current Path:");
	scanf_s("%24s", pDesiredfolder, (unsigned int)_countof(pDesiredfolder));
	strcat_s(pDesiredfolder, sizeof(pDesiredfolder), "\\");
	strcat_s(pFilepath, (unsigned int)_countof(pFilepath), pDesiredfolder);
	if (!CheckFolderPath(pFilepath)) {
		exit(-3);
	}
	printf("Please Enter Your Desired File Name and Format Under Your Chosen Folder: ");
	scanf_s("%64s", pFilename, (unsigned int)_countof(pFilename));
	printf("Filename's Buffer's Contetnt after strcat_s: %s\n", pFilename);
	strcat_s(pFilepath, (unsigned int)_countof(pFilepath), pFilename);
	printf("Filepath Buffer's Content After calling strcat_s: %s\n", pFilepath);
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