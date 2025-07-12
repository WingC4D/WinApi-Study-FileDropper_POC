#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

#include "SystemInteractors.h"

typedef struct _UserAnswer_t {
	LPWSTR string;
	BOOL in_index;
	unsigned length;
}
UserAnswer_t,* pUserAnswer_t;

void CheckIfAnswerIsIndex(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	pUserAnswer_t pAnswer_t,
	int *remainder,
	int *pPower2Raise2,
	int *i
);

BOOL UserIOTraverseFolders(
	void
);

BOOL UserInputDrives(
	LPWSTR pPath
);

BOOL UserInputFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

void AddFolder2PathString(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t
);

void AddFolder2PathIndex(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

