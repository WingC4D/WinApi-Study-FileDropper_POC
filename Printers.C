#include "Printers.h"
#include "choosers.h"
#include "ErrorHandlers.h"

void PrintMemoryError(LPCWSTR pCFPoint)
{
	wprintf(L"[X] Failed To Allocate Memory For %s!\nExiting With Error Code : % x\n", pCFPoint, GetLastError());
	return;
}

void PrintDrives(LPWSTR pPath)
{
	wprintf(L"Available Drives:\n");
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0)
	{
		printf("GetLogicalDrives Failed!\nExitig With Error Code: %x", GetLastError());
		exit(-10);
	}
	LPWSTR pAvailableCharacters = (LPWSTR)malloc(sizeof(WCHAR));
	if (pAvailableCharacters == NULL)
	{
		free(pPath);
		PrintMemoryError(L"The Available Drives Buffer");
		exit(-8);
	}
	unsigned int i = 0;
	WCHAR cBase = L'A';
	for (WCHAR iCount = 0; iCount < 26; iCount++)
	{
		if (bitmask & (1 << iCount))
		{
			pAvailableCharacters[i] = cBase + iCount;
			wprintf(L"- %c\n", cBase + iCount);
			i++;	
			pAvailableCharacters = (LPWSTR)realloc(pAvailableCharacters, i);
			if (pAvailableCharacters == NULL) 
			{
				free(pPath);
				PrintMemoryError("The Reallocation Of the Available Characters in Printers");
				exit(-21);
			}
		}
	}
	pAvailableCharacters[i] = L'\0';
	ChooseDrive(pPath ,pAvailableCharacters);
	free(pAvailableCharacters);
	return;
}

void PrintCWD(LPWSTR pPath)
{
	wprintf(L"Current Working Path: %s\n", pPath);
	return;
}

BOOL PrintUserName(void) 
{
	LPWSTR pUsername = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR)); //Assigning a Buffer for the current username to land at.
	if (pUsername == NULL) 
	{
		PrintMemoryError(L"The User Name Buffer");
		exit(-14);
	}
	LPDWORD pSizeofusername = (LPDWORD)malloc(8* sizeof(WCHAR)); //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	if (pSizeofusername == NULL) {
		free(pUsername);
		PrintMemoryError(L"The Username's Size Buffer");
		exit(-20);
	}
	if (GetUserNameW(pUsername, pSizeofusername) == 0)
	{
		printf("[X] GetUserNameA API Function Failed!\nError Code: %x\n", GetLastError());
		return FALSE;
	}
	wprintf(L"Username: %s\n", pUsername);
	RtlSecureZeroMemory(pUsername, (wcslen(pUsername) + 1));
	free(pSizeofusername);
	free(pUsername);
	return TRUE;
}

void PrintSubFolders(LPWSTR pPath) 
{
	LPWIN32_FIND_DATAW pFolder_data = (LPWIN32_FIND_DATAW)malloc(sizeof(WIN32_FIND_DATAW));//Allocating memory for a Find_Data Structure to hold the file's info
	if (!pFolder_data) {
		free(pPath);
		PrintMemoryError(L"Folder Data Structer");
		exit(-6);
	}
	wcscat_s(pPath, MAX_PATH, L"*");//Adding the needed wildcard for the search
	HANDLE hFile = FindFirstFileW(pPath, pFolder_data);//using the SearchBuffer to look under the Current Path.
	if (hFile == INVALID_HANDLE_VALUE) //checking if the search for the first File succeeded or not.
	{
		free(pFolder_data);
		free(pPath);
		wprintf(L"Failed To Scan Path (Couldn't Feth A File Hanlde).\nExiting With Error Code: %lu\n", GetLastError()); //If it didnt Print Out the Error Code
		exit(-11);
	}
	pPath[wcslen(pPath) - 1] = L'\0';//Deleting The Asteriks Wildcard that was used for the Search.
	int i = 0;//Running Index
	SIZE_T sArraySize = 4;//Array Size
	LPWIN32_FIND_DATAW aFolders = (LPWIN32_FIND_DATAW)malloc(sArraySize * sizeof(WIN32_FIND_DATAW));//Creating a buffer fit to hold a 100 folders !temporary!
	if (aFolders == NULL)
	{
		free(pPath);
		free(pFolder_data);
		FindClose(hFile);
		PrintMemoryError("The aFolders Buffer in PrintSubFolders");
		exit(-21);
	}
	if (pFolder_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)//Checking if the First Found File is a Folder or not using the bit "and" operator
	{
		wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cAlternateFileName, i); //print out the folder name and the id tag associated with it.
		aFolders[i] = *pFolder_data;//De-refencing the pointer tot the "FIND_DATA" struct to hold the struct itself
		i++;//increase the value of the counter by 1
	}
	while (FindNextFileW(hFile, pFolder_data)) //checks if there are any more files, while there are, the returned value is a BOOL holding "TRUE" else it is "FALSE"
	{
		if ((i == sArraySize / 2) && pFolder_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
		{
			sArraySize *= 2;
			aFolders = (LPWIN32_FIND_DATAW)realloc(aFolders, sArraySize * sizeof(WIN32_FIND_DATAW));
			if (aFolders == NULL) 
			{
				free(pPath);
				free(pFolder_data);
				FindClose(hFile);
				PrintMemoryError("The Reallocation of aFolders in PrintSubFolders");
				exit(-21);
			}
		}
		if (pFolder_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)//Checking if the file at hand is a folder
		{
			aFolders[i] = *pFolder_data;//Creating and entry for each fodler
			wprintf(L"[#] Folder Name - [ %s ] | id: [%d] \n", aFolders[i].cFileName, i);//wchar are a must and i'm printing the Folder's Name and it's ID
			i++;//Increase the Folders Held Index by 1
		}
	}
	free(pFolder_data);//Freeing the buffer holding the pointed to the "Find_DATA" struct
	if (!FindClose(hFile))
	{
		free(aFolders);
		free(pPath);
		wprintf(L"Failed to Close Handle! ErrorCode: %x\n", GetLastError());
		exit(-17);
	}
	ChooseSubFolder(pPath, aFolders, i);
	free(aFolders);
	return;
}

