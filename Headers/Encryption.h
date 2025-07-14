#pragma once
#include <Windows.h>
#include <stdio.h>
#include <math.h>

VOID XorByInputKey(
	IN PBYTE pShellcode,
	IN SIZE_T sShellcodeSize,
	IN PBYTE bKey,
	IN SIZE_T sKeySize
);





NTSTATUS SystemFunction032(
	void
);