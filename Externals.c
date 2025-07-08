#include "Externals.h"
void call(void)
{
	HMODULE hModule = GetModuleHandleA("DLL_Study.dll");// Attempting to get the handle of the DLL
	if (hModule == NULL)
	{
		printf("Failed To Find In Memory The Desired DLL Handle!\nAttempting To Fetch Library...\n");
		hModule = LoadLibraryA("DLL_Study.dll");// If the DLL is not loaded in memory, use LoadLibrary to load it
		if (hModule == NULL)
		{
			printf("Failed to Fetch Library Handle!\nExiting Program With Error Code: -21...\n");
			return;
		}
	}
	PVOID  pHelloWorld = GetProcAddress(hModule, "HelloWorld");//This Pointer Stores The Address in Memory The *Current* Process can Use to call the HelloWorld Function Defined in DLL_Study.dll
	// Typecasting pHelloWorld to be of type HelloWorldFunctionPointer
	HelloWorldFunctionPointer HelloWorld = (HelloWorldFunctionPointer)pHelloWorld;//This Is The Line Where We Gain Local Control Of The Extrnal Function In Our Execution Flow

	HelloWorld();//Calling The External Function In Our Process!
	return;
}
