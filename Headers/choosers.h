#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

#include "SystemInteractors.h"

BOOL ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);

void FolderPathCat(
	LPWSTR pPath,
	LPWSTR index_text,
	LPWSTR pAnswer,
	int *  file_index,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);
BOOL UserIODrives(LPWSTR pPath);
BOOL UserIOFolders(LPWSTR pPath, LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t);