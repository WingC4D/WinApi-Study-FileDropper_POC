#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

BOOL ChooseDrive(LPWSTR pPath,LPWSTR pAvailableCharacters);
BOOL ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);
HANDLE CreateVessel(LPWSTR pPath);
