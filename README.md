# WinAPI File System Navigator and Payload Dropper
---
## Project Overview
- This project is a command-line application developed in C that demonstrates a comprehensive understanding of the Windows API. 
- The application provides functionalities for file system navigation, file I/O operations, and dynamic-link library (DLL) manipulation. It serves as a practical exploration of core WinAPI features, memory management, and basic cybersecurity concepts.
---
## Core Features
* **File System Navigation**: The application programmatically enumerates all logical drives and enables users to traverse the file system directory structure.
* **Optimized User Input Processing**: Implements an O(log N) algorithm for parsing user input, allowing for efficient selection of files and directories by their numerical index.
* **File Creation and Manipulation**: Provides the capability to create new files ("payload vessels") in any user-specified directory within the navigated path.
* **Dynamic Memory Management**: Utilizes dynamic memory allocation and deallocation to efficiently manage data structures for storing file and directory information during runtime.
* **Error Handling**: Incorporates robust error handling mechanisms to manage invalid user inputs and non-existent file paths, with options for directory creation, retrying input, or exiting the application.
* **DLL Interaction**: Demonstrates the loading of an external DLL (`DLL_Study.dll`) and the invocation of its exported functions, showcasing an understanding of process memory and inter-process communication.
* **Payload Encryption**: Implements the RC4 encryption algorithm to encrypt and decrypt a payload, demonstrating a foundational knowledge of symmetric-key cryptography.
---
## Technical Implementation
The application's workflow is as follows:
1.  Upon execution, it retrieves and displays a list of all logical drives available on the system.
2.  The user selects a drive by its corresponding letter.
3.  The application then lists the files and sub-folders within the selected directory.
4.  The user can navigate deeper into the file system by selecting a sub-folder by its index or opt to create a new file in the current directory. The parsing of the numerical index for folder selection is handled by an O(log N) algorithm, where N is the number of files and folders.
5.  If a new folder is specified that does not exist, the application provides the user with options to create it, retry the input, or perform other actions.

- The DLL interaction functionality illustrates how to dynamically load a DLL, retrieve a pointer to an exported function, and execute it within the application's process space.
---
## Project Structure
The project is logically organized into `Headers` and `source` directories:
* **`Headers/`**: Contains all header file declarations for functions, data structures, and external libraries.
* **`source/`**: Contains the implementation of all C source code files, organized by functionality.
---
## Building the Project
To build this project, a C compiler compatible with the Windows API (e.g., Microsoft Visual C++) is required.
1.  **Compile `dllmain.c` as a DLL:**
    This file must be compiled into a Dynamic Link Library. From the MSVC command line, execute:
    ```bash
    cl /LD source\dllmain.c /FeDLL_Study.dll
    ```
    This will create `DLL_Study.dll`.

2.  **Compile the main application:**
    Compile all `.c` files in the `source` directory, linking against the necessary Windows libraries. From the MSVC command line, execute:
    ```bash
    cl source\*.c /link Shlwapi.lib
    ```
---
## Usage Instructions
1.  Compile both the `DLL_Study.dll` and the main executable as described above.
2.  Ensure that `DLL_Study.dll` is located in the same directory as the main executable.
3.  Execute the application from the command prompt:
    ```bash
    .\main.exe
    ```
4.  Follow the on-screen prompts to interact with the file system.
