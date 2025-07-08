#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>

void ChooseDrive(LPWSTR pPath,LPWSTR pAvailableCharacters);
void ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);
HANDLE CreateVessel(LPWSTR pPath);
