#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h> 
#include <stdio.h>

#include <shlwapi.h>
#include "Win32FindDataArray.h"

void PrintDrives(LPWSTR pPath);

void PrintCWD(LPWSTR pPath);

BOOL PrintUserName(void);

void PrintFilesArrayW(LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t);

void PrintMemoryError(LPCWSTR pCFPoint);