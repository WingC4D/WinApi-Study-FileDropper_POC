#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include "workers.h"
#include <string.h>
#include <Windows.h> 
#include <stdio.h>
#include <Shlwapi.h>
#include <wchar.h>

//#define MAX_PATH
#define _NO_CRT_STDIO_INLINE
#define longPathAware


LPWSTR ChooseSubDirectory(LPWSTR pPath) {
	LPWIN32_FIND_DATAW pFolder_data = malloc(sizeof(WIN32_FIND_DATAW));//Allocating memory for a Find_Data Structure to hold the file's info
	LPWSTR pSearch_buffer = malloc(MAX_PATH * sizeof(WCHAR));//Creating a temporary buffer to hold the path with the wildcard.
	wcscpy_s(pSearch_buffer, MAX_PATH, (LPCWSTR)pPath);//Copying the buffer to not conflict with the original one.
	wcscat_s(pSearch_buffer, MAX_PATH, L"*");//Adding the needed wildcard for the search
	HANDLE hFile = FindFirstFileW(pSearch_buffer, pFolder_data);//using the SearchBuffer to look under the Current Path.
	free(pSearch_buffer);//freeing the temporay buffer
	if (hFile == INVALID_HANDLE_VALUE) //checking if the search for the first File succeeded or not.
	{
		wprintf(L"Failed To Fetch A File Handle\nExiting With Error Code: %ul\n", GetLastError()); //If it didnt Print Out the Error Code
		return;//&End the Function's process.
	}
	else
	{
		int i = 0;//Genral counter my delete later if not needed.
		WIN32_FIND_DATAW ids[100];
		if (pFolder_data->dwFileAttributes == 16 || i == 99)//Checking if the First Found File is a Folder or not
		{
			wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cAlternateFileName, i); //If it Is print it out 
			ids[i] = *pFolder_data;
			i++;//increase the value of the counter by 1
		}

		while (FindNextFileW(hFile, pFolder_data)) //checks if there are any more files, while there are, the returned value is a BOOL holding "TRUE" else it is "FALSE"
		{
			if (pFolder_data->dwFileAttributes == 16)
			{
				wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cFileName, i);//wchar are a must and i'm printing the Folder's Name and it's ID
				ids[i] = *pFolder_data;
				i++;//Increase the Counter by 1
			}
		}
		for (int j = 0; j < i; j++) {
			wprintf(L"Folder: %s\nj: %d\n", ids[j].cFileName, j);
		}

		LPWSTR pAnswer = malloc(MAX_PATH);
		wscanf_s(L"%1s", pAnswer, MAX_PATH);
		(int)pAnswer[0];
		//wprintf(L"%d\n", pAnswer[0]);
		int ASCII_Value = pAnswer[0] - 48;
		wprintf(L"ASCII: %lu\n", ASCII_Value);
		if (0 <= ASCII_Value && ASCII_Value <= 9) {
			//wprintf(L"ids array item name: %s\n", ids[ASCII_Value].cFileName);
			pAnswer = ids[ASCII_Value].cFileName;
			
		}
		//pPath[strlen(pPath)]  = '\0';
		wcscat_s(pPath, MAX_PATH, (LPCWSTR)pAnswer);
		wprintf(L"Path: %s\n", pPath);
		
		free(pAnswer);
		printf("Freed pAnswer");
		if (FindClose(hFile) == FALSE)
		{
			printf("Failed to Close Handle! ErrorCode: %x\n", GetLastError());
		}
		system("PAUSE");
		return pPath;
	}
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

void static PrintCWD(LPWSTR pFilepath) {
	wprintf(L"Current Working Path: %s\n", pFilepath);
	return;
}

LPCWSTR ChooseDrive(LPWSTR pDesiredDrive) {
	LPWSTR pPrediseredDrive = malloc(24);
	pDesiredDrive[0] = L'\0';
	wprintf(L"Please Choose a Drive\n");
	wscanf_s(L"%1s", pPrediseredDrive, _countof(pPrediseredDrive) * sizeof(WCHAR));
	wprintf(L"%s\n", pPrediseredDrive);
	pPrediseredDrive[0] = towupper(pPrediseredDrive[0]);
	wcscat_s(pDesiredDrive, _countof(pDesiredDrive) * sizeof(WCHAR), (LPCSTR)pPrediseredDrive);
	//printf("input: %s\nInput Length: %lu\n", pPrediseredDrive, strlen(pPrediseredDrive));
	wcscat_s(pDesiredDrive, _countof(pDesiredDrive) * sizeof(WCHAR), L":\\");
	//printf("Targeted Character: %c", pDesiredDrive[0]);
	PrintCWD(pDesiredDrive);
	return (LPCWSTR)pDesiredDrive;
}

LPWSTR PrintDrives(LPWSTR pDesiredDrive)
{
	wprintf(L"Available Drives:\n");
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0) 
	{
		printf("GetLogicalDrives Failed!\nExitig With Error Code: %x", GetLastError());
	}
	CHAR cBase = 'A';
	for (CHAR iCount = 0; iCount < 26; iCount++) 
	{
		if (bitmask & (1 << iCount)) 
		{
			printf("- %c\n", cBase + iCount);
		}
	}
	
	return ChooseDrive(pDesiredDrive);
}

BOOL CheckFolderPath(LPWSTR pFilepath) 
{
	if (PathFileExistsW(pFilepath)) 
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
				BOOL create_dir_result = CreateDirectoryW(pFilepath, NULL);
				if (!create_dir_result)
				{
					wprintf(L"Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu", pFilepath, GetLastError());
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



