#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>
#include "SystemInteractors.h"

void PrintDrives(LPWSTR pPath);
void PrintCWD(LPWSTR pPath);
BOOL PrintUserName(void);
void PrintSubFiles(LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t);
void PrintMemoryError(LPCWSTR pCFPoint);