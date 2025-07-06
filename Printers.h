#pragma once
#include <Windows.h>

inline LPWSTR PrintDrives(LPWSTR pDesiredDrive);
inline void PrintCWD(LPWSTR pFilepath);
inline BOOL PrintUserName();
inline LPWSTR PrintSubFolders(LPWSTR pPath);
//#ifndef WMAX_PATH
//extern const DWORD WMAX_PATH;
//#endif
