#include "Printers.h"
#include "choosers.h"


LPWSTR PrintDrives()
{
	wprintf(L"Available Drives:\n");
	DWORD bitmask = GetLogicalDrives();
	if (bitmask == 0)
	{
		printf("GetLogicalDrives Failed!\nExitig With Error Code: %x", GetLastError());
		exit(-10);
	}
	
	LPSTR pAvailableCharacters =  malloc(26);
	if (!pAvailableCharacters)
	{
		free(pAvailableCharacters);
		printf("Failed To Allocate Memory For Drive Selection!\nExiting With Error Code: %x\n", GetLastError());
		exit(-8);
	}
	unsigned int i = 0;
	CHAR cBase = 'A';
	for (CHAR iCount = 0; iCount < 26; iCount++)
	{
		if (bitmask & (1 << iCount))
		{
			pAvailableCharacters[i] = cBase + iCount;
			printf("- %c\n", cBase + iCount);
			i++;	
		}
	}
	pAvailableCharacters[i] = '\0';//Setting the limit Of the "String" Area in the array the pointer points at
	LPWSTR pPath = ChooseDrive(pAvailableCharacters);
	free(pAvailableCharacters);
	return pPath;
}

void PrintCWD(LPWSTR pFilepath)
{
	wprintf(L"Current Working Path: %s\n", pFilepath);
	return;
}

BOOL PrintUserName() 
{
	DWORD uiLength = MAX_PATH * sizeof(WCHAR);
	LPWSTR pUsername = (LPWSTR)malloc(uiLength); //Assigning a Buffer for the current username to land at.
	LPDWORD pSizeofusername = (LPDWORD)malloc(8* sizeof(WCHAR)); //Assigning a buufer the Size of the username in chars (1 char = 1 byte) to land at.
	if (!GetUserNameW(pUsername, pSizeofusername))
	{
		printf("[-] GetUserNameA API Function Failed!\nError Code: %x\n", GetLastError());
		return FALSE;
	}
	wprintf(L"Username: %s\n", _Notnull_ pUsername);
	RtlSecureZeroMemory(_Notnull_ pSizeofusername, sizeof(*pSizeofusername) + 1);
	RtlSecureZeroMemory(_Notnull_ pUsername, wcslen(_Notnull_ pUsername) + 1);
	free(pSizeofusername);
	free(pUsername);
	return TRUE;
}

void PrintSubFolders(LPWSTR pPath) {
	LPWIN32_FIND_DATAW pFolder_data = malloc(sizeof(WIN32_FIND_DATAW));//Allocating memory for a Find_Data Structure to hold the file's info
	if (!pFolder_data) {
		free(pPath);
		free(pFolder_data);
		exit(-6);
	}
	wcscat_s(pPath, MAX_PATH, L"*");//Adding the needed wildcard for the search
	HANDLE hFile = FindFirstFileW(pPath, pFolder_data);//using the SearchBuffer to look under the Current Path.
	if (hFile == INVALID_HANDLE_VALUE) //checking if the search for the first File succeeded or not.
	{
		free(pFolder_data);
		free(pPath);
		wprintf(L"Failed To Scan Path (Couldn't Feth A File Hanlde.\nExiting With Error Code: %lu\n", GetLastError()); //If it didnt Print Out the Error Code
		exit(-11);
		//&End the Function's process.
	}
	pPath[wcslen(pPath) - 1] = L'\0';
	int i = 0;//Genral counter my delete later if not needed.
	WIN32_FIND_DATAW aFolders[100];//Creating a buffer fit to hold a 100 folders !temporary!
	if (pFolder_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY || i == 99)//Checking if the First Found File is a Folder or not using the bit "and" operator
	{
		wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cAlternateFileName, i); //print out the folder name and the id tag associated with it.
		aFolders[i] = *pFolder_data;//De-refencing the pointer tot the "FIND_DATA" struct to hold the struct itself
		i++;//increase the value of the counter by 1
	}
	
	while (FindNextFileW(hFile, pFolder_data)) //checks if there are any more files, while there are, the returned value is a BOOL holding "TRUE" else it is "FALSE"
	{
		if (pFolder_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)//Checking if the file at hand is a folder
		{
			wprintf(L"Folder Name - %s | Folder id - #%d\n", pFolder_data->cFileName, i);//wchar are a must and i'm printing the Folder's Name and it's ID
			aFolders[i] = *pFolder_data;//Creating and entry for each fodler
			i++;//Increase the Counter by 1
		}
	}
	free(pFolder_data);//Freeing the buffer holding the pointed to the "Find_DATA" struct
	if (FindClose(hFile) == FALSE)
	{
		printf("Failed to Close Handle! ErrorCode: %x\n", GetLastError());
	}
	ChooseSubFolder(pPath, aFolders, i);
	return pPath;
}

