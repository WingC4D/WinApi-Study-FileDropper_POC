#pragma once ("workers.h")
#include "workers.h";
#include <Windows.h> 
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

static void GetWorkingDisks() 
{
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0) {
		printf("GetLogicalDrives Failed!\nExitig With Error Code: %x", GetLastError());
	}
	char cBase = 'A';
	char iCount = 0;
	for (iCount = 0; iCount < 26; iCount++) {
		if (bitmask & (1 << iCount)) {
			printf("- %c\n", cBase + iCount);
		}
	}
	return;
};


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