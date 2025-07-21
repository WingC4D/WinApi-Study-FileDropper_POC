#include "ErrorHandlers.h"
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
	WCHAR pAnswer[2] = { L'\0' };
	wscanf_s(L"%1s", pAnswer, 2);
	switch (pAnswer[0])
	{
		case 'c':
		case 'C':
		{
			BOOL create_dir_result = CreateDirectoryW(pCandidatePath, NULL);
			if (!create_dir_result)
			{
				wprintf(L"Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu\n", pOriginalPath, GetLastError());
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
			return FALSE;
			break;
		}
		case 'f':
		case 'F':
		{
			wprintf(L"Going Back To Folder Selction In Path: %s\n", pOriginalPath);
			PrintFilesArrayW(pOriginalPath);
			return TRUE;
		}
		case 'd':
		case 'D':
		{
			return TRUE;
			break;
		}
		case 'p':
		case 'P':
		{
			wcscpy_s(pCandidatePath, wcslen(pCandidatePath) + 1, pOriginalPath);
			wprintf(L"You Are Creating A Payload Vessel Under: %s\n", pCandidatePath);
			CreateVessel(pCandidatePath);
			return FALSE;
			break;
		}
		default:
		{
			wprintf(L"Your Input Is Incoherant With Provided Options.\nPlease Choose A Valid Answer.\n");
			return FolderDebugger(pCandidatePath, pOriginalPath);
			break;
		}

	}
}

