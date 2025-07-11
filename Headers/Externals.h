#pragma once
#include <Windows.h>
#include<stdio.h>
typedef void(WINAPI* HelloWorldFunctionPointer)();
// Constructing a new data type that represents HelloWorld's function pointer.

void call(
	void
);