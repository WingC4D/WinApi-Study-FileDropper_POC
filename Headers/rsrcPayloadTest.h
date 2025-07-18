#pragma once

#include<Windows.h>
#include <stdio.h>
#include "resource.h"
#include "Encryption.h"
#include <time.h>


typedef struct _TEXT {
	PVOID pText;
	DWORD  sText;
}TEXT, *LPTEXT;

PBYTE Test(void);