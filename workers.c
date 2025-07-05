#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include "workers.h"
#include <string.h>
#include <Windows.h> 
#include <stdio.h>
#include <Shlwapi.h>
#include <wchar.h>

#define _NO_CRT_STDIO_INLINE
#define longPathAware


LPSTR ChooseSubDirectory(LPSTR pPath) {
	LPWIN32_FIND_DATAA pFolder_data =  malloc(sizeof(WIN32_FIND_DATAA));
	LPSTR pSearch_buffer = malloc(MAX_PATH);
	strcpy_s(pSearch_buffer, MAX_PATH, pPath);
	strcat_s(pSearch_buffer, MAX_PATH, "*");
	printf("pSearch_buffer: %s\npPath: %s\n", pSearch_buffer, pPath);
	HANDLE hFile = FindFirstFileA(pSearch_buffer, pFolder_data);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		wprintf(L"Failed To Fetch A File Handle\nExiting With Error Code: %ul\n", GetLastError());
		return;
	}
	else 
	{
		int i = 0;
		wprintf(L"FileName For File#%d: %s\n", i, pFolder_data->cAlternateFileName);
		while (FindNextFile(hFile, pFolder_data) == TRUE) {
			if (pFolder_data->dwFileAttributes == 16) 
			{
				i++;
				wprintf(L"Folder Num: #%lu\n", i);
				wprintf(L"Folder Name: %s\n", pFolder_data->cFileName);
			}
		}
		LPSTR pAnswer = malloc(MAX_PATH);
		scanf_s("%24s", pAnswer, MAX_PATH);
		pPath[strlen(pPath)] = '\0';
		strcat_s(pPath, MAX_PATH, pAnswer);
	}
	FindClose(hFile);
	system("PAUSE");
	return pPath;
}

BOOL PrintUserName() {
	void* pUsername = malloc(512); //Assigning a Buffer for the current username to land at.
	LPDWORD pSizeofusername = malloc(8); //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	BOOL bGetusername_result = GetUserNameA(pUsername, pSizeofusername);
	if (!bGetusername_result) {
		printf("[-] GetUserNameA API Function Failed!\nError Code: %x\n", GetLastError());
		return FALSE;
	}
	//printf("Sizeof Username: %lu\n", *pSizeofusername);
	printf("Username: %s\n", (char *)pUsername);
	printf("Size Of User Name (with null terminator) in bytes: %lu\n", *pSizeofusername);
	RtlSecureZeroMemory((void *)pSizeofusername, sizeof( *pSizeofusername) + 1);
	RtlSecureZeroMemory(pUsername, strlen(pUsername) + 1);
	printf("What's left of pSizeofusername: %ul\n", *pSizeofusername);
	printf("What's left of pUsername: %s\n", (LPSTR) pUsername);
	free(pSizeofusername);
	free(pUsername);
	return TRUE;
}

void static PrintCWD(LPSTR pFilepath) {
	printf("Current Working Path: %s\n", pFilepath);
	return;
}

LPCSTR ChooseDrive(LPSTR pDesiredDrive) {
	CHAR pPrediseredDrive[2]; 
	pDesiredDrive[0] = '\0';
	printf("Please Choose a Drive\n");
	scanf_s("%1s", pPrediseredDrive, sizeof(pPrediseredDrive));
	pPrediseredDrive[0] = toupper(pPrediseredDrive[0]);
	strcat_s(pDesiredDrive, _countof(pDesiredDrive), (LPCSTR)pPrediseredDrive);
	//printf("input: %s\nInput Length: %lu\n", pPrediseredDrive, strlen(pPrediseredDrive));
	strcat_s(pDesiredDrive, _countof(pDesiredDrive), ":\\");
	//printf("Targeted Character: %c", pDesiredDrive[0]);
	PrintCWD(pDesiredDrive);
	return (LPCSTR)pDesiredDrive;
}

LPCSTR PrintDrives(LPSTR pDesiredDrive)
{
	printf("Available Drives:\n");
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0) 
	{
		printf("GetLogicalDrives Failed!\nExitig With Error Code: %x", GetLastError());
	}
	char cBase = 'A';
	for (char iCount = 0; iCount < 26; iCount++) 
	{
		if (bitmask & (1 << iCount)) 
		{
			printf("- %c\n", cBase + iCount);
		}
	}
	pDesiredDrive = ChooseDrive(pDesiredDrive);
	return (LPCSTR)pDesiredDrive;
}

BOOL CheckFolderPath(LPCSTR pFilepath) 
{
	if (PathFileExistsA(pFilepath)) 
	{
		return TRUE;
	}
	else
	{
		printf("The Desired Directory Does Not Exist Under The Current Path.\n Would You Like To Make One?\nEnter [Y | y] Yes. / [N/n] No.\n");
		char pAnswer[2];
		if (scanf_s("%1s", pAnswer, sizeof(pAnswer)) != 1)
		{
			printf("Error reading input. Please try again.\n");
		}
		switch (pAnswer[0])
		{
			case 'y':
			case 'Y':
			{
				BOOL create_dir_result = CreateDirectoryA(pFilepath, NULL);
				if (!create_dir_result)
				{
					printf("Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu", pFilepath, GetLastError());
					return create_dir_result;
					break;
				}
				else
				{
					printf("Created The Desired Folder Successfully!\n");
					return create_dir_result;
					break;
				}
			}
			case 'n':
			case 'N':
			{
				printf("OK :(\nExiting Program With Exit Code: -3");
				return FALSE;
				break;
			}
			default:
			{
				return CheckFolderPath(pFilepath);
				break;
			}
		}
	}
}

