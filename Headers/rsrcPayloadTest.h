#pragma once

#include<Windows.h>
#include <stdio.h>
#include "resource.h"


typedef struct _PAYLOAD {
	PVOID pPayloadAddress;
	LPDWORD  dwpPayloadSize;
}PAYLOAD, *LPPAYLOAD;

LPPAYLOAD Test(void);