#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>



BOOL UserDebugger(LPWSTR pFilepath); //inline is there to pervent multiple definitions of  the function due to the logic's Deffinition is in the workers.C file definition 
LPWSTR ChooseDrive(LPWSTR pDesiredDrive, PCHAR pAvailableCharacters);
LPWSTR ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);
HANDLE CreatePayload(LPWSTR pPath);