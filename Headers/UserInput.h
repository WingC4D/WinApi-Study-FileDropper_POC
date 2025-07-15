#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <shlwapi.h>
#include "Win32FindDataArray.h"

typedef struct _UserAnswer_t *pUserAnswer_t;

BOOL HandleStringDrives(
	LPWSTR pPath,
	LPWSTR pAnswer
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

typedef struct _UserAnswer_t
{
	LPWSTR string;
	BOOL in_index;
	unsigned length;
}UserAnswer_t;


BOOL CheckUserInputFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	pUserAnswer_t pAnswer_t
);

void IsInputIndexed(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	pUserAnswer_t pAnswer_t
);

BOOL UserInputContinueFolders(
	void
);

BOOL UserInputDrives(
	LPWSTR pPath
);

BOOL UserInputFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

