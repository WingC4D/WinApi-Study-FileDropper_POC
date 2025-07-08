#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"

HANDLE CreatePayload(LPWSTR pPath) 
{
	wprintf(L"Please Enter Your Desired File Name and Format Under Your Chosen Folder: \n");
	LPWSTR pFilename = malloc(MAX_PATH * sizeof(WCHAR));
	wscanf_s(L"%64s", pFilename, MAX_PATH);
	wcscat_s(pPath, MAX_PATH, pFilename);
	free(pFilename);
	PrintCWD(pPath);
	HANDLE hFile = CreateFileW((LPCWSTR)pPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 128, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed To Create The Payload! :(\nExiting With Error Code: %lu\n", GetLastError());
		CloseHandle(hFile);
		free(pPath);

		exit (-5);
	}
	return hFile;
}

void ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i) 
{
	size_t sPathWordCount = (size_t)(wcslen(pPath) + 1);
	LPWSTR pOriginalPath = malloc(MAX_PATH * sizeof(WCHAR));
	wcscpy_s(pOriginalPath, sPathWordCount, pPath);
	if (pOriginalPath == NULL) {
		free(pPath);
		PrintMemoryError(L"Original Path Copy Buffer In ChooseSubFolder");
		exit(-11);
	}
	size_t sCharacters = (MAX_PATH - wcslen(pPath) - 1) ;
	LPWSTR pAnswer = malloc(sCharacters * sizeof(WCHAR));//creating a wchar buffer with a WinAPI datatype for the user's answer
	if (!pAnswer) 
	{
		free(pPath);
		free(pOriginalPath);
		PrintMemoryError(L"The User's Answer In ChooseSubFolder");
		exit(-12);
	}
	wscanf_s(L"%64s", pAnswer, sCharacters);//Scan for the desired folder name; options include the ID or a full string
	int ASCII_Value = (int)pAnswer[0] - 48;
	if (0 <= ASCII_Value && (ASCII_Value <= 9 && ASCII_Value <= i))
	{
		wcscpy_s(pAnswer, sCharacters, aFolders[ASCII_Value].cFileName);
	}
	wcscat_s(pPath, sCharacters, pAnswer);
	wcscat_s(pPath, sCharacters, L"\\");
	PrintCWD(pPath);
	if (!FolderDebugger(pPath, pOriginalPath))
	{
		free(pOriginalPath);
		//free(pPath);
		free(pAnswer);
		exit(-13);
	}
	free(pAnswer);	
	return;
}

void ChooseDrive(LPWSTR pPath, LPWSTR pValidCharacters)
{
	LPWSTR pAnswer = calloc(2, sizeof(WCHAR));
	if (pAnswer == NULL)
	{
		PrintMemoryError(L"The User's Answer In ChooseDrive");
		free(pPath);
		free(pValidCharacters);
		exit(-19);
	}
	wprintf(L"Please Choose a Drive\n");
	wscanf_s(L"%1s", pAnswer, 2);
	pAnswer[0] = towupper(pAnswer[0]);
	wprintf(L"pAnwer: %s\n", pAnswer);
	unsigned int uiAmount = (unsigned int)wcslen(pValidCharacters);
	//start cut
	for (unsigned int i = 0; i < uiAmount; i++)
	{
		if (pAnswer[0] == pValidCharacters[i])
		{
			break;
		}
		if (i == uiAmount - 1)
		{
			free(pAnswer);
			printf("Please Chose A Valid Drive\n");
			return PrintDrives(pPath);
		}
	}
	//end 
	wcscpy_s(pPath, MAX_PATH, pAnswer);
	free(pAnswer);
	wcscat_s(pPath, MAX_PATH, L":\\");
	PrintCWD(pPath);
	return;
}

