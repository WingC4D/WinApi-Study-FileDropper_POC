#pragma once
#include <Windows.h>
#include <stdio.h>
BOOLEAN WritePayloadToRegistry
(
	IN PUCHAR pPayload,
	IN DWORD  dwPayloadSize
);
BOOLEAN ReadRegKeys
(
	OUT unsigned char **pPayloadAddress[],
	OUT PSIZE_T psPayloadSize
);