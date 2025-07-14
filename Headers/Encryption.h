#pragma once
#include <Windows.h>
#include <stdio.h>
#include <math.h>

typedef struct _RC4Context
{
	unsigned int  main_index;
	unsigned int  swap_index;
	unsigned char stream_key[256];

}RC4CONTEXT, * PRC4CONTEXT;


void rc4Init(PRC4CONTEXT context, const unsigned char* key, size_t length);

void rc4Cipher(PRC4CONTEXT context, const unsigned char* input, unsigned char* output, size_t length);

void RC4Init(
	PRC4CONTEXT pContext_t,
	const unsigned char *p_key,
	size_t s_length
);

void RC4Encrypt(
	PRC4CONTEXT          pContext_t,
	const unsigned char* pInput,
	unsigned char* pOutput,
	size_t               sLength
);

VOID XorByInputKey(
	IN PBYTE p_shellcode,
	IN SIZE_T s_shellcode,
	IN PBYTE p_key,
	IN SIZE_T s_key
);

NTSTATUS SystemFunction032(
	void 
);