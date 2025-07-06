#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include<stdio.h>

LPWSTR PrintDrives(LPWSTR pDesiredDrive);
void PrintCWD(LPWSTR pFilepath);
BOOL PrintUserName();
LPWSTR PrintSubFolders(LPWSTR pPath);
