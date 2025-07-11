#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

#include "SystemInteractors.h"

typedef struct _UserAnswer_t {
	LPWSTR data;
	BOOL in_index;
	unsigned length;
}
UserAnswer_t,
* pUserAnswer_t;

BOOL ChooseSubFolder(
	LPWSTR pPath,
	LPWIN32_FIND_DATAW aFolders, 
	int i
);

void FolderPathCat(
	LPWSTR  pPath,
	WCHAR * pAnswer,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

BOOL UserIOTraverseFolders(
	void
);

BOOL UserIODrives(
	LPWSTR pPath
);

void TextFolderPathCat(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t
);

void NumFolderPathCat(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

BOOL UserIOFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);