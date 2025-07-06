#include "Printers.h"

LPWSTR PrintDrives(LPWSTR pDesiredDrive)
{
	wprintf(L"Available Drives:\n");
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0)
	{
		printf("GetLogicalDrives Failed!\nExitig With Error Code: %x", GetLastError());
	}
	unsigned int i = 0;
	char *pPossibleCharacters =  (char *)malloc(26);
	CHAR cBase = 'A';
	for (CHAR iCount = 0; iCount < 26; iCount++)
	{
		if (bitmask & (1 << iCount))
		{
			pPossibleCharacters[i] = cBase + iCount;
			printf("- %c\n", cBase + iCount);
			i++;	
		}
	}
	LPSTR pAvailableCharacters = malloc(i + 1);
	pPossibleCharacters[i] = '\0';
	strcpy_s(pAvailableCharacters, i + 1, pPossibleCharacters);
	free(pPossibleCharacters);
	return ChooseDrive(pDesiredDrive, pAvailableCharacters);
}

void PrintCWD(LPWSTR pFilepath)
{
	wprintf(L"Current Working Path: %s\n", pFilepath);
	return;
}

BOOL PrintUserName() {
	DWORD uiLength = MAX_PATH * sizeof(WCHAR);
	LPWSTR pUsername = (LPWSTR)malloc(uiLength); //Assigning a Buffer for the current username to land at.
	LPDWORD pSizeofusername = malloc(8* sizeof(WCHAR)); //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	if (!GetUserNameW(pUsername, pSizeofusername))
	{
		printf("[-] GetUserNameA API Function Failed!\nError Code: %x\n", GetLastError());
		return FALSE;
	}
	wprintf(L"Username: %s\n", pUsername);
	RtlSecureZeroMemory(pSizeofusername, sizeof(*pSizeofusername) + 1);
	RtlSecureZeroMemory(pUsername, strlen(pUsername) + 1);
	free(pSizeofusername);
	free(pUsername);
	return TRUE;
}

LPWSTR PrintSubFolders(LPWSTR pPath) {
	LPWIN32_FIND_DATAW pFolder_data = malloc(sizeof(WIN32_FIND_DATAW));//Allocating memory for a Find_Data Structure to hold the file's info
	LPWSTR pSearch_buffer = malloc(MAX_PATH * sizeof(WCHAR));//Creating a temporary buffer to hold the path with the wildcard.
	wcscpy_s(pSearch_buffer, MAX_PATH, (LPCWSTR)pPath);//Copying the buffer to not conflict with the original one.
	wcscat_s(pSearch_buffer, MAX_PATH, L"*");//Adding the needed wildcard for the search
	HANDLE hFile = FindFirstFileW(pSearch_buffer, pFolder_data);//using the SearchBuffer to look under the Current Path.
	free(pSearch_buffer);//freeing the temporay buffer
	if (hFile == INVALID_HANDLE_VALUE) //checking if the search for the first File succeeded or not.
	{
		wprintf(L"Failed To Fetch A File Handle\nExiting With Error Code: %ul\n", GetLastError()); //If it didnt Print Out the Error Code
		return pPath;//&End the Function's process.
	}
	int i = 0;//Genral counter my delete later if not needed.
	WIN32_FIND_DATAW aFolders[100];//Creating a buffer fit to hold a 100 folders
	if (pFolder_data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY || i == 99)//Checking if the First Found File is a Folder or not using the bit "and" operator
	{
		wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cAlternateFileName, i); //print out the folder name and the id tag associated with it.
		aFolders[i] = *pFolder_data;//De-refencing the pointer tot the "FIND_DATA" struct to hold the struct itself
		i++;//increase the value of the counter by 1
	}
	while (FindNextFileW(hFile, pFolder_data)) //checks if there are any more files, while there are, the returned value is a BOOL holding "TRUE" else it is "FALSE"
	{
		if (pFolder_data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)//Checking if the file at hand is a folder
		{
			wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cFileName, i);//wchar are a must and i'm printing the Folder's Name and it's ID
			aFolders[i] = *pFolder_data;//Creating and entry for each fodler
			i++;//Increase the Counter by 1
		}
	}
	if (FindClose(hFile) == FALSE)
	{
		printf("Failed to Close Handle! ErrorCode: %x\n", GetLastError());
	}
	free(pFolder_data);//Freeing the buffer holding the pointed to the "Find_DATA" struct
	ChooseSubFolder(pPath, aFolders, i);
	if (!UserDebugger(pPath)) 
	{
		exit(-3);
	}
	return pPath;
}

