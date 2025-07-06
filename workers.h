#pragma once
#include <Windows.h>
inline BOOL CheckFolderPath(LPWSTR pFilepath); //inline is there to pervent multiple definitions of  the function due to the logic's Deffinition is in the workers.C file definition 
inline LPWSTR PrintDrives(LPWSTR pDesiredDrive);
inline LPCWSTR ChooseDrive(LPWSTR pDesiredDrive);
inline void PrintCWD(LPCWSTR pFilepath);
inline LPWSTR ChooseSubDirectory(LPWSTR pPath);
inline BOOL PrintUserName();
#define longPathAware