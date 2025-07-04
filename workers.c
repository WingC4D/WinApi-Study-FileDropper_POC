#pragma once ("workers.h")
#include "workers.h";
#include <Windows.h> 
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

BOOL check_folder_path(LPCSTR pFilepath) {
	if (PathFileExistsA(pFilepath)) {
		return TRUE;
	}
	else {
		printf("Folder Does Not Exisist Under User's.\n Would You Like To Make One?\nEnter [Y | y] Yes. / [N/n] No.\n");
		char pAnswer[2];
		if (scanf_s("%1s", pAnswer, sizeof(pAnswer)) != 1) {
			printf("Error reading input. Please try again.\n");
		}
		else if (pAnswer[0] == 'y' || pAnswer[0] == 'Y') {
			BOOL create_dir_result = CreateDirectoryA(pFilepath, NULL);
			if (!create_dir_result) {
				printf("Failed To Create A New Folder In The Desired Path!:\nPath: %s\nExiting With Error Code: %lu", pFilepath, GetLastError());
				return create_dir_result;
			}
			else {
				printf("Created The Desired Foolder Successfully!\n");
				return create_dir_result;
			}
		}
		else if (pAnswer[0] == 'n' || pAnswer[0] == 'N') {
			printf("OK :(\nExiting Program With Exit Code: -3");
			return FALSE;
		}
		else {
			return check_folder_path(pFilepath);
		}
	}
}