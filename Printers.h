#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

LPWSTR PrintDrives();
void PrintCWD(LPWSTR pPath);
BOOL PrintUserName();
void PrintSubFolders(LPWSTR pPath);
