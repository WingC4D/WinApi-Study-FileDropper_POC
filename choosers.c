#include "choosers.h"
#include "Printers.h"
#include "main.h"


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
	LPWSTR pOriginalPath = malloc((wcslen(pPath) + 1) * sizeof(WCHAR));
	if (!pOriginalPath) {
		free(pPath);
		free(pOriginalPath);
		printf("Failed To Allocate Memory For The Original Path!\nExiting With Error Code: %x\n", GetLastError());
		exit(-11);
	}
	size_t sCharacters = (MAX_PATH - wcslen(pPath) - 1) ;
	LPWSTR pAnswer = malloc(sCharacters * sizeof(WCHAR));//creating a wchar buffer with a WinAPI datatype for the user's answer
	if (!pAnswer) 
	{
		free(pPath);
		free(pOriginalPath);
		free(pAnswer);
		printf("Failed To Allocate Memory For The User's Answer!\nExiting With ErrorCode: %x\n", GetLastError());
		exit(-12);
	}
	wscanf_s(L"%64s", pAnswer, sCharacters);//Scan for the desired folder name; options include the ID or a full string
	int ASCII_Value = (int)pAnswer[0] - 48;
	if (0 <= ASCII_Value && (ASCII_Value <= 9 && ASCII_Value <= i))
	{
		wcscpy_s(pAnswer, sCharacters, aFolders[ASCII_Value].cFileName);
	}
	wcscat_s(pPath, sCharacters, (LPCWSTR)pAnswer);
	wcscat_s(pPath, sCharacters, L"\\");
	PrintCWD(pPath);
	if (!FolderDebugger(pPath, pOriginalPath))
	{
		free(pPath);
		free(pOriginalPath);
		free(pAnswer);
		exit(-13);
	}
	free(pOriginalPath);
	free(pAnswer);	
	return;
}

LPWSTR ChooseDrive(LPSTR pValidCharacters)
{
	LPWSTR pAnswer = calloc(5, sizeof(WCHAR));
	wprintf(L"Please Choose a Drive\n");
	wscanf_s(L"%1s", pAnswer, 5);
	pAnswer[0] = towupper(pAnswer[0]);
	wprintf(L"Buffer's Contents %s\n", pAnswer);
	unsigned int uiAmount = (unsigned int)strlen(pValidCharacters);
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
			return ChooseDrive(pValidCharacters);
		}
	}
	//end 
	LPWSTR pPath = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
	wcscpy_s(pPath, MAX_PATH, pAnswer);
	free(pAnswer);
	wcscat_s(pPath, MAX_PATH, L":\\");
	PrintCWD(pPath);
	return pPath;
}

BOOL FolderDebugger(LPWSTR pCandidatePath, LPWSTR pWorkingPath) 
{
	
	if (PathFileExistsW(pCandidatePath)) 
	{
		return TRUE;
	}
	printf("The Desired Folder Does Not Exist Under The Current Path.\n");
	printf("- To Create The Specified Folder Under The Current Path Press: [ C | c ]\n- To Exit Press: [ Q | q ]\n");
	printf("- To Retry Entring A New Folder Name Press: [ F | f ]\n- To Choose A New Drive Press: [ D | d ]\n");
	printf("- To Discard The Inputed And Create The Payload File In The Current Path Press: [ P | p ]\n");
	PCHAR pAnswer = malloc(2);
	scanf_s("%1s", pAnswer, 2);
	switch (pAnswer[0])
	{
		case 'c':
		case 'C':
		{
			BOOL create_dir_result = CreateDirectoryW(pCandidatePath, NULL);
			if (!create_dir_result)
			{
				wprintf(L"Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu\n", pWorkingPath, GetLastError());
				free(pAnswer);
				return FALSE;
				
			}
			wcscpy_s(pWorkingPath, MAX_PATH, pCandidatePath);
			printf("Created The Desired Folder Successfully!\n");
			break;	
		}
		case 'q':
		case 'Q':
		{
			printf("OK :(\nExiting Program With Exit Code: -3\n");
			free(pAnswer);
			return FALSE;
			
		}
		case 'f':
		case 'F': 
		{
			free(pCandidatePath);//Freeing the Candidate Buffer because a new one is created in "PrintSubFolders()"" and i don't Want orphan pointers
			wprintf(L"Going Back To Folder Selction In Path: %s\n", pWorkingPath);
			PrintSubFolders(pWorkingPath);
			free(pAnswer);
			return FALSE;
		}
		case 'd':
		case 'D': 
		{
			free(pCandidatePath);
			free(pWorkingPath);
			free(pAnswer);
			return main();
		}
		case 'p':
		case 'P': 
		{
			free(pCandidatePath);
			free(pAnswer);
			wprintf(L"You Are Creating A Payload Vessel Under: %s\n", pWorkingPath);
			return CreatePayload(pWorkingPath);			
		}
		default:
		{
			printf("Your Input Is Incoherant With Provided Options.\nPlease Choose A Valid Answer.\n");
			free(pAnswer);
			return FolderDebugger(pCandidatePath ,pWorkingPath);
		}
	}
}

