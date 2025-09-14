#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <shlwapi.h>
#include "Win32FindDataArray.h"

typedef struct _UserAnswer_t
{
	CHAR* string;
	USHORT length;
}
UserAnswer_t, *pUserAnswer_t;


BOOL HandleStringDrives
(
	LPWSTR pPath,
	LPWSTR pAnswer
);

void AddFolder2PathString
(
	LPWSTR pPath,
	PCHAR  pAnswer,
	USHORT sAnswer
);

void AddFolder2PathIndex
(
	LPWSTR pPath,
	PWCHAR  pAnswer,
	USHORT sAnswer,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

BOOL CheckUserInputFolders
(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	pUserAnswer_t pAnswer_t
);

BOOL IsInputIndexed
(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	PWCHAR pAnswer_t,
	USHORT sAnswer 
);

BOOL UserInputContinueFolders
(
	void
);

BOOL UserInputDrives
(
	LPWSTR pPath
);

VOID UserInputFolders
(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);
