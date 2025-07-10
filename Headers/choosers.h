#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>


BOOL ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);
BOOL UserIODrives(LPWSTR pPath);