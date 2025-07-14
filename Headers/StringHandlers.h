#pragma once
#include <Windows.h>
#include "choosers.h"


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