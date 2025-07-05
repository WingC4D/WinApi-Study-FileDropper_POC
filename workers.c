#pragma once ("workers.h")
#include <string.h>
#include "workers.h";
#include <Windows.h> 
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

static void PrintUserName() {
	void* pUsername = malloc(512); //Assigning a Buffer for the current username to land at.
	LPDWORD pSizeofusername = malloc(8); //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	BOOL bGetusername_result = GetUserNameA(pUsername, pSizeofusername);
	if (!bGetusername_result) {
		printf("[-] GetUserNameA API Function Failed!\nError Code: %x\n", GetLastError());
		return -1;
	}
	//printf("Sizeof Username: %lu\n", *pSizeofusername);
	printf("Username: %s\n", (char*)pUsername);
	printf("Size Of User Name (with null terminator) in bytes: %lu\n", *pSizeofusername);
	RtlSecureZeroMemory(pSizeofusername, strlen((char*)pSizeofusername) + 1);
	RtlSecureZeroMemory(pUsername, strlen((char*)pUsername) + 1);
	printf("What's left of pSizeofusername: %s\n", *pSizeofusername);
	printf("What's left of pUsername:%s\n", pUsername);
	free(pSizeofusername);
	free(pUsername);
}

void static PrintCWD(LPSTR pFilepath) {
	printf("Current Working Path: %s\n", pFilepath);
	return;
}



LPCSTR ChooseDrive(LPSTR pDesiredDrive) {
	CHAR pPrediseredDrive[2]; //prepared for wchars
	pDesiredDrive[0] = '\0';
	printf("Please Choose a Drive!\n");
	scanf_s("%1s", pPrediseredDrive, sizeof(pPrediseredDrive));
	strcat_s(pDesiredDrive, _countof(pDesiredDrive), (LPCSTR)pPrediseredDrive);
	//printf("input: %s\nInput Length: %lu\n", pPrediseredDrive, strlen(pPrediseredDrive));
	strcat_s(pDesiredDrive, _countof(pDesiredDrive), ":\\");
	//printf("Targeted Character: %c", pDesiredDrive[0]);
	pDesiredDrive[0] = toupper(pDesiredDrive[0]);
	printf("Output in ChooseDrive: %s\n", pDesiredDrive);
	return (LPCSTR)pDesiredDrive;
}

LPCSTR PrintDrives(LPSTR pDesiredDrive)
{
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
	printf("contents in printdrives: %s\n", pDesiredDrive);
	PrintCWD(pDesiredDrive);
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
/*
void ListDir(LPCSTR pDirectorypath) {

}
*/