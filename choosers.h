#pragma once
#include <Windows.h>

inline BOOL CheckFolderPath(LPWSTR pFilepath); //inline is there to pervent multiple definitions of  the function due to the logic's Deffinition is in the workers.C file definition 
inline LPWSTR ChooseDrive(LPWSTR pDesiredDrive);
inline LPWSTR ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i);
inline HANDLE CreatePayload(LPWSTR pPath);