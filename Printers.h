#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

BOOL PrintDrives(LPWSTR pPath, LPWSTR pAvailableCharacters);
void PrintCWD(LPWSTR pPath);
BOOL PrintUserName(void);
BOOL PrintSubFolders(LPWSTR pPath);
void PrintMemoryError(LPCWSTR pCFPoint);