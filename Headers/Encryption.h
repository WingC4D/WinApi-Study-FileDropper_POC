#pragma once
#pragma comment(lib, "bcrypt.lib")
#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>


#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) > -1)

#define KEYSIZE				32

#define IVSIZE				16

typedef struct _AES
{
	PBYTE pPText;
	DWORD sPText;

	PBYTE pCText;
	DWORD sCText;

	PBYTE pKey;
	PBYTE pInitVec;

	BOOL blEncrypt;
}AEStruct, *PAEStruct;

typedef struct _CUSTOM_USTRING 
{
	unsigned long Length;
	unsigned long MaximumLength;
	void         *pBuffer;
}USTRING, * PUSTRING;

typedef NTSTATUS(NTAPI *pfnSystem032)(
	PUSTRING data,
	PUSTRING key
);

typedef struct Context
{
	unsigned int  main_index;
	unsigned int  swap_index;
	unsigned char pKey[256];

}Context, *pContext;

BOOL aInit(
	IN  PVOID  pPText,
	IN  DWORD  sPText,
	IN  PBYTE  pKey,
	IN  PBYTE  pInitVec,
	OUT PVOID  pCText,
	OUT PDWORD psCText
);

BOOL aFin(
	IN  PVOID  pCText,
	IN  DWORD  sCText,
	IN  PBYTE  pKey,
	IN  PBYTE  pInitVec,
	OUT PVOID* pPText,
	OUT PDWORD spPText
);

BOOL InstallAes(
	IN OUT PAEStruct pA_t
);

BOOL AESSuccessCheck(
	PBOOL pSTATE, 
	NTSTATUS STATUS, 
	LPSTR function
);

VOID PrintHexData(
	LPCSTR pName, 
	PBYTE pData, 
	SIZE_T size
);

VOID GenerateRandomBytes(
	PBYTE pByte,
	SIZE_T size
);

BOOL rInit(
	pContext pContext_t,
	unsigned char pKey[256],
	size_t sKeyLength
);

void rFin(
	pContext          pContext_t,
	unsigned char    *pInput,
	unsigned char    *pOutput,
	size_t            sPayloadLength
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