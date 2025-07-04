#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include "workers.c"

#pragma comment(lib, "Shlwapi.lib")

#define _CRT_SECURE_NO_WARNINGS

int main(void) {
	void* pUsername = malloc(512); //Assigning a Buffer for the current username to land at.
	LPDWORD pSizeofusername = malloc(8); //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	BOOL bGetusername_result = GetUserNameA(pUsername, pSizeofusername);
	if (!bGetusername_result) {
		printf("[-] GetUserNameA API Function Failed!\nError Code: %x\n", GetLastError());
		return -1;
	}

	printf("Username: %s\n", (char*)pUsername);

	printf("Size Of User Name (with null terminator) in bytes: %lu\n", *pSizeofusername);

	char pFilepath[512];

	char pDesiredfolder[96];

	char pFilename[256];

	printf("Please Enter Your Desired Folder Under Users: ");

	scanf_s("%24s", pDesiredfolder, _countof(pDesiredfolder));

	strcpy_s(pFilepath, _countof(pFilepath), "C:\\Users\\\0");

	strcat_s(pUsername, sizeof(pUsername), "\\");

	strcat_s(pDesiredfolder, sizeof(pDesiredfolder), "\\");

	strcat_s(pFilepath, _countof(pFilepath), (const char*)pUsername);

	strcat_s(pFilepath, _countof(pFilepath), pDesiredfolder);

	if (!check_folder_path(pFilepath)) {

		exit(-3);

	}

	printf("Please Enter Your Desired File Name and Format Under Your Chosen Folder: ");

	scanf_s("%64s", pFilename, _countof(pFilename));

	printf("Filename's Buffer's Contetnt after strcat_s: %s\n", pFilename);

	strcat_s(pFilepath, _countof(pFilepath), pFilename);

	printf("Filepath Buffer's Content After calling strcat_s: %s\n", pFilepath);

	printf("Press 'Enter' To Exit! :)");

	return 0;

}



/*

LPWSTR pFilepath = L"C:\\Users\\\0";

L"\\Desktop\\mmc.c";

HANDLE hFile = INVALID_HANDLE_VALUE;

hFile = CreateFileW(pFilepath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

if (hFile == INVALID_HANDLE_VALUE) {

printf("[-] CreateFileW API Function Failed!\nError Code: %x\n", GetLastError());

return -1;

}

printf("[+] CreateFileW Succeeded!\nFile Handle Address: %p\n", hFile);

*/