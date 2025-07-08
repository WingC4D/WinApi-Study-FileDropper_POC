#include "Printers.h"
#include "choosers.h"
#include "ErrorHandlers.h"

// Constructing a new data type that represents HelloWorld's function pointer.
typedef void(WINAPI* HelloWorldFunctionPointer)();


void PrintMemoryError(LPCWSTR pCFPoint)
{
	wprintf(L"[X] Failed To Allocate Memory For %s!\nExiting With Error Code : % x\n", pCFPoint, GetLastError());
	return;
}

BOOL PrintDrives(LPWSTR pPath, LPWSTR pAvailableCharacters)
{
	
	wprintf(L"Available Drives:\n");
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0)
	{
		printf("[X] GetLogicalDrives Failed!\n[X] Exitig With Error Code: %x", GetLastError());
		return FALSE;
	}
	unsigned int i = 0;
	WCHAR cBase = L'A';
	for (WCHAR iCount = 0; iCount < 26; iCount++)
	{
		if (bitmask & (1 << iCount))
		{
			pAvailableCharacters[i] = cBase + iCount;
			wprintf(L"[#] %c\n", cBase + iCount);
			i++;
		}
	}
	return TRUE;
}

void PrintCWD(LPWSTR pPath)
{
	wprintf(L"Current Working Path: %s\n", pPath);
	return;
}

BOOL PrintUserName(void) 
{
	WCHAR pUsername[MAX_PATH] = { L'\0' }; //Assigning a Buffer for the current username to land at.
	DWORD pSizeofusername[8] = { NULL }; //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	if (GetUserNameW(pUsername, pSizeofusername) == 0)
	{
		printf("[X] GetUserNameA API Function Failed!\n[X] Error Code: %x\n", GetLastError());
		return FALSE;
	}
	wprintf(L"[#] Username: %s\n", pUsername);
	RtlSecureZeroMemory(pUsername, (wcslen(pUsername) + 1));//For Fun.
	return TRUE;
}

BOOL PrintSubFolders(LPWSTR pPath) 
{
	WIN32_FIND_DATAW folder_data_t = { NULL };//Allocating memory for a Find_Data Structure to hold the file's info
	
	wcscat_s(pPath, MAX_PATH, L"*");//Adding the needed wildcard for the search
	HANDLE hFile = FindFirstFileW(pPath, &folder_data_t);//using the SearchBuffer to look under the Current Path.
	if (hFile == INVALID_HANDLE_VALUE) //checking if the search for the first File succeeded or not.
	{
		FindClose(hFile);
		wprintf(L"Failed To Scan Path (Couldn't Feth A File Hanlde).\nExiting With Error Code: %lu\n", GetLastError()); //If it didnt Print Out the Error Code
		return FALSE;
	}
	pPath[wcslen(pPath) - 1] = L'\0';//Deleting The Asteriks Wildcard that was used for the Search.
	int i = 0;//Running Index
	SIZE_T sArraySize = 4;//Array Size
	LPWIN32_FIND_DATAW paFolders = (LPWIN32_FIND_DATAW)malloc(sArraySize * sizeof(WIN32_FIND_DATAW));//Creating a buffer fit to hold a 100 folders !temporary!
	if (paFolders == NULL)
	{
		FindClose(hFile);
		PrintMemoryError(L"The aFolders Buffer in PrintSubFolders");
		return FALSE;
	}
	if (folder_data_t.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)//Checking if the First Found File is a Folder or not using the bit "and" operator
	{
		wprintf(L"[%d] Folder Name - %s\n", folder_data_t.cAlternateFileName, i); //print out the folder name and the id tag associated with it.
		paFolders[i] = folder_data_t;//De-refencing the pointer tot the "FIND_DATA" struct to hold the struct itself
		i++;//increase the value of the counter by 1
	}
	while (FindNextFileW(hFile, &folder_data_t)) //checks if there are any more files, while there are, the returned value is a BOOL holding "TRUE" else it is "FALSE"
	{

		if ((i == sArraySize / 2) && folder_data_t.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
		{
			sArraySize *= 2;
			LPWIN32_FIND_DATAW pTemp = (LPWIN32_FIND_DATAW)realloc(paFolders, sArraySize * sizeof(WIN32_FIND_DATAW));
			if (pTemp == NULL) 
			{
				free(paFolders);
				FindClose(hFile);
				PrintMemoryError(L"The Reallocation of aFolders in PrintSubFolders");
				return FALSE;
			}
			paFolders = pTemp;
			
		}
		if (folder_data_t.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)//Checking if the file at hand is a folder
		{
			paFolders[i] = folder_data_t;//Creating and entry for each fodler
			wprintf(L"[#] Folder Name - [ %s ] | id: [ %d ] \n", paFolders[i].cFileName, i);//wchar are a must and i'm printing the Folder's Name and it's ID
			i++;//Increase the Folders Held Index by 1
		}
	}
	//free(folder_data_t);//Freeing the buffer holding the pointed to the "Find_DATA" struct
	if (!FindClose(hFile))
	{
		free(paFolders);
		printf("[X] Failed to Close Handle!\n[X] Exiting With ErrorCode: %x\n", GetLastError());
		return FALSE;
	}
	if (ChooseSubFolder(pPath, paFolders, i) == FALSE) 
	{
		free(paFolders);
		printf("[X] Failed To Choose SubFolder!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return FALSE;
	}
	free(paFolders);
	return TRUE;
}

