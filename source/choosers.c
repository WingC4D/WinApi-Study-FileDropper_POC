#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"
#include "SystemInteractors.h"







BOOL ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i) 
{
	SIZE_T OccupiedCharacters = (SIZE_T)(wcslen(pPath) + 1);//Calculating The Amount Of Wchar's Lef
	LPWSTR pOriginalPath = calloc(OccupiedCharacters , sizeof(WCHAR));
	if (pOriginalPath == NULL)
	{ 
		PrintMemoryError(L"Original Path Copy Buffer In ChooseSubFolder");
		exit(-11);//
	}
	wcscpy_s(pOriginalPath, OccupiedCharacters, pPath);
	unsigned int sUnOccupiedCharacters = ((size_t)MAX_PATH - OccupiedCharacters) ;//
	LPWSTR pAnswer = malloc(sUnOccupiedCharacters * sizeof(WCHAR));//creating a wchar buffer with a WinAPI datatype for the user's answer
	if (pAnswer == NULL) 
	{
		free(pOriginalPath);
		PrintMemoryError(L"The User's Answer In ChooseSubFolder");
		return FALSE;
	}
	pAnswer[0] = L'\0';
	wscanf_s(L"%64s", pAnswer, sUnOccupiedCharacters);//Scan for the desired folder name; options include the ID or a full string
	int ASCII_Value = (int)pAnswer[0] - 48;
	if (0 <= ASCII_Value && (ASCII_Value <= 9 && ASCII_Value <= i))
	{
		wcscpy_s(pAnswer, sUnOccupiedCharacters, aFolders[ASCII_Value].cFileName);
	}
	wcscat_s(pPath, sUnOccupiedCharacters, pAnswer);
	wcscat_s(pPath, sUnOccupiedCharacters, L"\\");
	PrintCWD(pPath);
	if (!FolderDebugger(pPath, pOriginalPath))
	{
		free(pOriginalPath);
		free(pAnswer);
		return FALSE;
	}
	free(pOriginalPath);
	free(pAnswer);	
	return TRUE;
}

