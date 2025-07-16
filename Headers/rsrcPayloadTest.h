#pragma once

#include<Windows.h>
#include <stdio.h>
#include "resource.h"
#include "Encryption.h"

typedef struct _TEXT {
	PVOID pText;
	DWORD  sText;
}TEXT, *LPTEXT;

LPTEXT Test(void);