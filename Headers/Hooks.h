#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "SystemInteraction.h"

BOOLEAN HookWithVirtualAlloc
(
    IN     PVOID  pFunctionToHook,
    IN     PVOID  pAddressOfMyCode,
    IN     DWORD  sHookLength
);
