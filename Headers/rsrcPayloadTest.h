#pragma once

#include<Windows.h>
#include <stdio.h>
#include "resource.h"
#include "Encryption.h"

typedef struct _PAYLOAD {
	PVOID pPayloadAddress;
	DWORD  dwPayloadSize;
}PAYLOAD, *LPPAYLOAD;

LPPAYLOAD Test(void);