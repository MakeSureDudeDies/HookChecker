#include <Windows.h>

#include <tchar.h>
#include <iostream>
#include <print>
#include <vector>
#include <array>

#include <TlHelp32.h>
#include <winnt.h>
#include <assert.h>

HANDLE GetProcessHandle(const wchar_t* ProcessName) {
    DWORD PIDWithHighestThreadCount = 0;
    DWORD HighestThreadCount = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(hSnap, &pe))
    {
        if ((_tcsicmp(pe.szExeFile, ProcessName) == 0) && (pe.cntThreads > HighestThreadCount))
        {
            HighestThreadCount = pe.cntThreads;
            PIDWithHighestThreadCount = pe.th32ProcessID;
        }
    }

    CloseHandle(hSnap);

    if (PIDWithHighestThreadCount != 0) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, PIDWithHighestThreadCount);
    }
    else {
        // No process found.
        return NULL;
    }
}

bool CheckHooked(HANDLE ProcessHandle, const char* ModuleName, const char* ExportName) {
    // We will check the first 25 bytes here, why bother more?
    // Ghetto code incoming.

    HMODULE ModuleHandle = GetModuleHandleA(ModuleName);

    if (!ModuleHandle) { // if we get there, idk how we failed so bad.
        std::println("GetModuleHandleA Failed. Error Code: 0x{:X}", GetLastError());
        return false;
    }

    void* FuncAddress = (void*)GetProcAddress(ModuleHandle, ExportName);

    if (!FuncAddress) {
        std::println("GetProcAddress Failed. Error Code: 0x{:X}", GetLastError());
        return false;
    }

    std::vector<BYTE> Buffer(25);
    if (!ReadProcessMemory(ProcessHandle, FuncAddress, Buffer.data(), Buffer.size(), nullptr)) {
        std::println("ReadProcessMemory Failed. Error Code: 0x{:X}", GetLastError());
        return false;
    }

    std::vector<BYTE> CurrentProcessBuffer(25);
    memcpy(CurrentProcessBuffer.data(), FuncAddress, Buffer.size());
    
    if (memcmp(Buffer.data(), CurrentProcessBuffer.data(), 25) != 0) {
        if (Buffer[0] != 0xE9 && Buffer[0] == CurrentProcessBuffer[0] || strcmp(ExportName, "KiUserInvertedFunctionTable") == 0) { // first check is jmp second is first byte match
            std::println("{} ( 0x{:X} ) in {} is hooked (Possible false flag)", ExportName, (uintptr_t)FuncAddress, ModuleName);
        }
        else {
            std::println("{} ( 0x{:X} ) in {} is hooked", ExportName, (uintptr_t)FuncAddress, ModuleName);
        }
        
        std::print("Process Bytes: ");

        for (int i = 0; i <= Buffer.size() - 1; i++) {
            if (Buffer[i] < 0x10) {
                std::print("0{:X} ", Buffer[i]);
            }
            else {
                std::print("{:X} ", Buffer[i]);
            }
        }

        std::println("");

        std::print("Expected Bytes: ");

        for (int i = 0; i <= CurrentProcessBuffer.size() - 1; i++) {
            if (CurrentProcessBuffer[i] < 0x10) {
                std::print("0{:X} ", CurrentProcessBuffer[i]);
            }
            else {
                std::print("{:X} ", CurrentProcessBuffer[i]);
            }
        }

        std::print("\n\n");
    }

    return true;
}

void WalkExportsAndCheck(HANDLE ProcessHandle, const char* ModuleName) {
    HMODULE ModuleHandle = GetModuleHandleA(ModuleName);
    if (ModuleHandle) {
        if (reinterpret_cast<IMAGE_DOS_HEADER*>(ModuleHandle)->e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS* Header = (IMAGE_NT_HEADERS*)((BYTE*)ModuleHandle + ((IMAGE_DOS_HEADER*)ModuleHandle)->e_lfanew);
            if (Header->Signature == IMAGE_NT_SIGNATURE) {
                if (Header->OptionalHeader.NumberOfRvaAndSizes > 0) {
                    IMAGE_EXPORT_DIRECTORY* Exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ModuleHandle + Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    if (Exports->AddressOfNames != 0) {
                        DWORD* Names = (DWORD*)((BYTE*)ModuleHandle + Exports->AddressOfNames);
                        for (int i = 0; i <= Exports->NumberOfNames - 1; i++) {
                            CheckHooked(ProcessHandle, ModuleName, reinterpret_cast<const char*>(ModuleHandle) + Names[i]);
                        }
                    }
                }
            }
        }
    }
}