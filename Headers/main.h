#pragma once
#pragma comment(lib, "kernel32.lib")
#include "RegstryPayloadStaging.h"
#include "Obfuscation.h"
#include "WebRetrival.h"
#include "UserInput.h"
#include "SystemInteraction.h"
#include "ErrorHandlers.h"
#include "Printers.h"
#include "Win32FindDataArray.h"
#include "rsrcPayloadTest.h"
#include "Externals.h"
#include "Encryption.h"
#include  "dllinjection.h"

#define		SACRIFICIAL_DLL          "User32.dll"
#define		SACRIFICIAL_FUNC         "MessageBoxA"
#define     SPOOFED_COMMAND_LINE     L"powershell.exe Totally Legit Argument"
#define		MALICIOUS_COMMAND_LINE   L"powershell.exe -NoExit calc.exe"


typedef  VOID(WINAPI* fnShellCode)();