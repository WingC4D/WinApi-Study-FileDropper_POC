#pragma once
#include <Windows.h>
#include <stdio.h>
#include <math.h>

typedef struct _A
{
	PBYTE pInText;
	DWORD sInText;

	PBYTE pOutText;
	DWORD sOutText;
	
	PBYTE pK;
	DWORD sK;
}A, *pA;

typedef struct _CUSTOM_USTRING 
{
	unsigned long Length;
	unsigned long MaximumLength;
	void         *pBuffer;
}USTRING, * PUSTRING;

typedef NTSTATUS(NTAPI* fnSystem032) (
	PUSTRING data,
	PUSTRING key
);

typedef struct Context
{
	unsigned int  main_index;
	unsigned int  swap_index;
	unsigned char pKey[256];

}Context, * pContext;

BOOL aInit(
	IN  PVOID  pInText,
	IN  DWORD  sInText,
	IN  PBYTE  pK,
	IN  PBYTE  pInitVec,
	OUT PVOID  pOutText,
	OUT PDWORD psOutText
);

void rInit(
	pContext pContext_t,
	unsigned char *pKey,
	size_t sKeyLength
);

void rFin(
	pContext          pContext_t,
	unsigned char *pInput,
	unsigned char       *pOutput,
	size_t               sPayloadLength
);

VOID xInit(
	IN PBYTE p_shellcode,
	IN SIZE_T s_shellcode,
	IN PBYTE p_key,
	IN SIZE_T s_key
);

NTSTATUS SystemFunction032(
	byte* pKey,
	byte* pData,
	unsigned long sKey,
	unsigned long sData
);

NTSTATUS SystemFunction033(
	byte* pKey,
	byte* pData,
	unsigned long sKey,
	unsigned long sData
);