#pragma once
#pragma comment(lib, "Shlwapi.lib")

#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

#include "choosers.h"
#include "Printers.h"
#include "Printers.c"


#define _NO_CRT_STUDIO_INLINE

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
	free(pAnswer);
	return pPath;
}

LPCWSTR ChooseDrive(LPWSTR pDesiredDrive) 
{
	LPWSTR pPrediseredDrive = (LPWSTR)malloc(6* sizeof(WCHAR));
	unsigned int uiBufferlength = _countof(pDesiredDrive);
	pDesiredDrive[0] = L'\0';
	wprintf(L"Please Choose a Drive\n");
	wscanf_s(L"%1s", pPrediseredDrive, uiBufferlength);
	pPrediseredDrive[0] = towupper(pPrediseredDrive[0]);
	wcscat_s(pDesiredDrive, uiBufferlength, (LPCSTR)pPrediseredDrive);
	free(pPrediseredDrive);
	wcscat_s(pDesiredDrive, uiBufferlength, L":\\");
	PrintCWD(pDesiredDrive);
	return (LPCWSTR)pDesiredDrive;
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
