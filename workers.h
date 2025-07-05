#pragma once
#include <Windows.h>
inline BOOL CheckFolderPath(LPCSTR pFilepath); //inline is there to pervent multiple definitions of  the function due to the logic's Deffinition is in the workers.C file definition 
inline LPCSTR PrintDrives(LPSTR pDesiredDrive);
inline LPCSTR ChooseDrive(LPSTR pDesiredDrive);
inline void PrintCWD(LPCSTR pFilepath);