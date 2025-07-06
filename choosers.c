#pragma once
#pragma comment(lib, "Shlwapi.lib")

#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

#include "choosers.h"
#include "Printers.h"
#include "Printers.c"

HANDLE CreatePayload(LPWSTR pPath) 
{
	wprintf(L"Please Enter Your Desired File Name and Format Under Your Chosen Folder: \n");
	LPWSTR pFilename = VirtualAlloc(0, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	wscanf_s(L"%64s", pFilename, MAX_PATH);
	VirtualFree(pFilename, MAX_PATH, MEM_FREE);
	wcscat_s(pPath, MAX_PATH, pFilename);
	PrintCWD(pPath);
	HANDLE hFile = CreateFileW((LPCWSTR)pPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 128, NULL);
	free(pPath);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed To Create The Payload! :(\nExiting With Error Code: %x\n", GetLastError());
		exit (-5);
	}
	return hFile;
}

LPWSTR ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i) 
{
	LPWSTR pAnswer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));//creating a wchar buffer with a WinAPI datatype for the user's answer
	wscanf_s(L"%64s", pAnswer, MAX_PATH);//Scan for the desired folder name; options include the ID or a full string
	int ASCII_Value = (int)pAnswer[0] - 48;
	if (0 <= ASCII_Value && (ASCII_Value <= 9 && ASCII_Value <= i))
	{
		wcscpy_s(pAnswer, MAX_PATH, aFolders[ASCII_Value].cFileName);
	}
	wcscat_s(pPath, MAX_PATH, (LPCWSTR)pAnswer);
	wcscat_s(pPath, MAX_PATH, L"\\");
	PrintCWD(pPath);
	free(pAnswer);
	return pPath;
}

LPWSTR ChooseDrive(LPWSTR pDesiredDrive, PCHAR pValidCharacters) 
{	
	LPWSTR pPrediseredDrive = (LPWSTR)malloc(6* sizeof(WCHAR));
	unsigned int uiBufferlength = _countof(pDesiredDrive);
	pDesiredDrive[0] = L'\0';
	wprintf(L"Please Choose a Drive\n");
	wscanf_s(L"%1s", pPrediseredDrive, uiBufferlength);
	pPrediseredDrive[0] = towupper(pPrediseredDrive[0]);
	unsigned int uiAmount = strlen(pValidCharacters);
	//start cut
	for (unsigned int i = 0; i < uiAmount; i++) 
	{
		if (pPrediseredDrive[0] == pValidCharacters[i]) 
		{
			break;
		}
		if (i == uiAmount - 1) 
		{
			printf("Please Chose A Valid Drive\n");
			return ChooseDrive(pDesiredDrive, pValidCharacters);
		}
	}
	//end cut
	free(pValidCharacters);
	wcscat_s(pDesiredDrive, uiBufferlength, (LPCSTR)pPrediseredDrive);
	free(pPrediseredDrive);
	wcscat_s(pDesiredDrive, uiBufferlength, L":\\");
	PrintCWD(pDesiredDrive);
	return pDesiredDrive;
}

BOOL UserDebugger(LPWSTR pFilepath) 
{
	if (PathFileExistsW(pFilepath)) 
	{
		return TRUE;
	}
	printf("The Desired Folder Does Not Exist Under The Current Path.\n");
	printf("- To Create The Specified Folder Under The Current Path Press: [C | c]\n- To Exit Press: [Q | q]\n");
	printf("- To Retry Entring A New Folder Name Press: [R | r]\n");
	printf("- To Discard The Inputed And Create The Payload File In The Current Path Press: [P | p]\n");
	PCHAR pAnswer = (PCHAR)malloc(2);
	scanf_s("%1s", pAnswer, sizeof(pAnswer));
	switch (pAnswer[0])
	{
		case 'c':
		case 'C':
		{
			BOOL create_dir_result = CreateDirectoryW(pFilepath, NULL);
			if (!create_dir_result)
			{
				wprintf(L"Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu", pFilepath, GetLastError());
				return create_dir_result;
				break;
			}
			printf("Created The Desired Folder Successfully!\n");
			return create_dir_result;
			break;	
		}
		case 'q':
		case 'Q':
		{
			printf("OK :(\nExiting Program With Exit Code: -3");
			return FALSE;
			break;
		}
		default:
		{
			printf("Your Input Is Incoherant With Provided Options.\nPlease Choose A Valid Answer.\n");
			return UserDebugger(pFilepath);
			break;
		}
	}
}

