#pragma once

#include<Windows.h>
#include "SystemInteraction.h"
#include <stdio.h>
#include "Encryption.h"
#include <time.h>


typedef struct _PAYLOAD {
	
	PUCHAR  pText;
	size_t sText;

}PAYLOAD, *lpPAYLOAD;

lpPAYLOAD Test();



VOID StatusCheck(
	IN PUCHAR pInitVec,
	IN PUCHAR pKey,
	IN PUCHAR pData,
	IN size_t sData,
	IN PCHAR pName
);