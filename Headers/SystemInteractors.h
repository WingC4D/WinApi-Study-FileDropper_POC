#pragma once

#include <Windows.h>
#include <stdio.h>


void FetchSubFolders(LPWSTR pPath);
void FetchDrives(LPWSTR pPath);
BOOL CACDrives(LPWSTR pPath, WCHAR* pAnswer);
HANDLE CreateVessel(LPWSTR pPath);
