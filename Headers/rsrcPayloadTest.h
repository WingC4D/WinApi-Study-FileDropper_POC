#pragma once

#include<Windows.h>
#include <stdio.h>
#include "resource.h"
#include "Encryption.h"
#include <time.h>

typedef struct _RESOURCE {

	PVOID  pAddress;
	size_t sSize;

}RESOURCE, *PRESOURCE;

typedef struct _TEXT {
	
	PVOID pText;
	DWORD sText;

}TEXT, *LPTEXT;

PBYTE Test();

BOOL FetchResource(OUT PRESOURCE pResource_t);

VOID StatusCheck(
	IN PUCHAR pInitVec,
	IN PUCHAR pKey,
	IN PUCHAR pData,
	IN size_t sData,
	IN PCHAR pName
);