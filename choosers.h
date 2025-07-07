#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h> 
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>



BOOL FolderDebugger(LPWSTR pCandidatePath, LPWSTR pWorkingPath); //inline is there to pervent multiple definitions of  the function due to the logic's Deffinition is in the workers.C file definition 
LPWSTR ChooseDrive(LPSTR pAvailableCharacters);
void ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);
HANDLE CreatePayload(LPWSTR pPath);
