#include "ErrorHandlers.h"
#include "choosers.h"
#include "main.h"
#include "Printers.h"


BOOL FolderDebugger(LPWSTR pCandidatePath, LPWSTR pOriginalPath)
{

	if (PathFileExistsW(pCandidatePath))
	{
		return TRUE;
	}
	printf("The Desired Folder Does Not Exist Under The Current Path.\n");
	printf("- To Create The Specified Folder Under The Current Path Press: [ C | c ]\n- To Exit Press: [ Q | q ]\n");
	printf("- To Retry Entring A New Folder Name Press: [ F | f ]\n- To Choose A New Drive Press: [ D | d ]\n");
	printf("- To Discard The Inputed And Create The Payload File In The Current Path Press: [ P | p ]\n");
	LPWSTR pAnswer = (LPWSTR)malloc(2 * sizeof(WCHAR));
	if (!pAnswer) 
	{
		PrintMemoryError(L"The User's Answer in Folder Debugger");
	}
	wscanf_s(L"%1s", pAnswer, 2);
	if (wcslen(pAnswer) < 1) {
		wprintf(L"Failed To Catch The User's Answer!\nExiting With Error Code: %x\n", GetLastError());
		exit(-18);
	}
	switch (pAnswer[0])
	{
		case 'c':
		case 'C':
		{
			BOOL create_dir_result = CreateDirectoryW(pCandidatePath, NULL);
			if (!create_dir_result)
			{
				wprintf(L"Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu\n", pOriginalPath, GetLastError());
				free(pAnswer);
				return FALSE;
			}
			wcscpy_s(pOriginalPath, MAX_PATH, pCandidatePath);
			printf("Created The Desired Folder Successfully!\n");
			break;
		}
		case 'q':
		case 'Q':
		{
			wprintf(L"OK :(\nExiting Program With Exit Code: -13\n");
			free(pOriginalPath);
			free(pCandidatePath);
			free(pAnswer);
			exit(-13);

		}
		case 'f':
		case 'F':
		{
			wprintf(L"Going Back To Folder Selction In Path: %s\n", pOriginalPath);
			PrintSubFolders(pOriginalPath);
			free(pAnswer);
			return TRUE;
		}
		case 'd':
		case 'D':
		{
			//free(pOriginalPath);
			free(pAnswer);
			return main();
		}
		case 'p':
		case 'P':
		{
			wcscpy_s(pCandidatePath, wcslen(pCandidatePath) + 1, pOriginalPath);
			free(pOriginalPath);
			free(pAnswer);
			wprintf(L"You Are Creating A Payload Vessel Under: %s\n", pCandidatePath);
			CreateVessel(pCandidatePath);
			return FALSE;
		}
		default:
		{
			wprintf(L"Your Input Is Incoherant With Provided Options.\nPlease Choose A Valid Answer.\n");
			free(pAnswer);
			return FolderDebugger(pCandidatePath, pOriginalPath);
		}
		free(pAnswer);
		return TRUE;
	}
}

