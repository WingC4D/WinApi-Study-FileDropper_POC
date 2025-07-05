#pragma once
#include <Windows.h>
inline BOOL CheckFolderPath(LPCSTR pFilepath); //inline is there to pervent multiple definitions of  the function due to the logic's Deffinition is in the workers.C file definition 
inline static void GetWorkingDisks();