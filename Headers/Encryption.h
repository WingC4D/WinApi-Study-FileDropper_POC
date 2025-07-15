#pragma once
#include <Windows.h>
#include <stdio.h>
#include <math.h>

typedef struct _CUSTOM_USTRING 
{
	DWORD Length;
	DWORD MaximumLength;
	PVOID pBuffer;
}USTRING, * PUSTRING;

typedef struct _RC4Context
{
	unsigned int  main_index;
	unsigned int  swap_index;
	unsigned char pKey[256];

}RC4CONTEXT, * PRC4CONTEXT;

void RC4Init(
	PRC4CONTEXT pContext_t,
	unsigned char *pKey,
	size_t sKeyLength
);

void RC4Encrypt(
	PRC4CONTEXT          pContext_t,
	unsigned char *pInput,
	unsigned char       *pOutput,
	size_t               sPayloadLength
);

VOID BasicStreamXor(
	IN PBYTE p_shellcode,
	IN SIZE_T s_shellcode,
	IN PBYTE p_key,
	IN SIZE_T s_key
);

NTSTATUS SystemFunction032(
	PUSTRING pData,
	PUSTRING pKey
);