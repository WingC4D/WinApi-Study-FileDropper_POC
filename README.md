## WinAPI Study: File Dropper Proof-of-Concept

This project is a console application developed in C, demonstrating various interactions with the Windows API. It serves as a proof-of-concept for navigating the file system, creating files, and interacting with external Dynamic Link Libraries (DLLs).

### Features

* **Drive Enumeration:** Identifies and lists all logical drives available on the system.
* **File System Navigation:** Allows users to choose a drive and then browse through sub-folders by selecting them via an index.
* **Efficient Index Processing:** Employs an O(log N) algorithm (where N is the number of files/folders) in `choosers.c` to efficiently parse and validate user input when selecting a folder by its numerical index, based on the magnitude of the index.
* **File Creation ("Payload Vessel"):** Creates a new file at a user-specified location within the navigated path.
* **Dynamic Memory Management:** Manages dynamic memory allocation and deallocation for storing file information during navigation.
* **Basic Error Handling:** Includes mechanisms to handle non-existent paths, providing options to create new directories, retry input, or exit.
* **External DLL Interaction (Commented Out):** Demonstrates how to load an external DLL (`DLL_Study.dll`) and call an exported function (`HelloWorld`) from it. This feature is present in the code but commented out in the `main` function.

### How it Works

The application guides the user through the following steps:

1.  Upon execution, it retrieves and displays a list of available logical drives (e.g., `C:\`, `D:\`).
2.  The user selects a drive by entering its corresponding letter.
3.  The application then lists the files and sub-folders within the chosen directory.
4.  The user can either select a sub-folder by its index to navigate deeper or choose to create a new file in the current directory. The parsing of the numerical index for folder selection is handled by an O(log N) algorithm (where N is the count of files/folders).
5.  If a new folder is specified but doesn't exist, the application prompts the user to create it, retry, or take other actions.

The Call functionality showcases how to dynamically load a DLL, obtain a pointer to an exported function, and execute it within the application's process space.

### Project Structure

The project is organized into `Headers` and `source` directories:

* **`Headers/`**:
    * `ErrorHandlers.h`: Declarations for functions handling path and directory creation errors.
    * `Externals.h`: Declarations related to external DLL interaction.
    * `Printers.h`: Declarations for console printing utility functions.
    * `SystemInteractors.h`: Declarations for core file system interaction functions and data structures.
    * `choosers.h`: Declarations for user input handling and path manipulation.
    * `main.h`: Main function declaration.

* **`source/`**:
    * `ErrorHandlers.c`: Implementations for error handling and user prompts related to directory existence.
    * `Externals.c`: Implementation for loading and calling functions from an external DLL.
    * `Printers.c`: Implementations for functions that print information to the console, such as drives, current working directory, and sub-files.
    * `SystemInteractors.c`: Implementations for functions interacting directly with the Windows file system, including fetching drives, creating files, and managing file data arrays.
    * `choosers.c`: Implementations for handling user input for drive and folder selection, and constructing file paths.
    * `dllmain.c`: Source code for the `DLL_Study.dll`, containing the exported `HelloWorld` function.
    * `main.c`: The main entry point of the application, orchestrating the calls to other modules.

### Building the Project

To build this project, you will need a C compiler compatible with Windows API (e.g., Microsoft Visual C++).

1.  **Compile `dllmain.c` as a DLL:**
    This file needs to be compiled into a Dynamic Link Library.
    Example (using MSVC command line):
    ```bash
    cl /LD dllmain.c /FeDLL_Study.dll
    ```
    Place `DLL_Study.dll` in a `Libraries` subfolder relative to your executable, or in the same directory as the main executable.

2.  **Compile the main application:**
    Compile all `.c` files in the `source` directory, linking against necessary Windows libraries.
    Example (using MSVC command line):
    ```bash
    cl main.c SystemInteractors.c Printers.c choosers.c ErrorHandlers.c Externals.c /link Shlwapi.lib Kernel32.lib User32.lib
    ```

### Usage

1.  Compile both the `DLL_Study.dll` and the main executable.
2.  Ensure `DLL_Study.dll` is located where the main executable can find it (e.g., in a `Libraries` subfolder or the same directory).
3.  Run the executable from your command prompt:
    ```bash
    .\YourExecutableName.exe
    ```
4.  Follow the on-screen prompts to interact with the file system.
