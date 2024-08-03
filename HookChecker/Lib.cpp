#include <Windows.h>

#include <tchar.h>
#include <iostream>
#include <print>
#include <vector>
#include <thread>

#include <TlHelp32.h>
#include <shlwapi.h>
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
        std::println("GetModuleHandleA Failed for {}. Error Code: 0x{:X}", ModuleName, GetLastError());
        return false;
    }

    void* FuncAddress = (void*)GetProcAddress(ModuleHandle, ExportName);

    if (!FuncAddress) {
        std::println("GetProcAddress Failed for {} ( Export Name: {} ). Error Code: 0x{:X}", ModuleName, ExportName, GetLastError());
        return false;
    }

    std::vector<BYTE> Buffer(25);

    DWORD OldProtection;
    if (!VirtualProtectEx(ProcessHandle, FuncAddress, Buffer.size(), PAGE_EXECUTE_READWRITE, &OldProtection)) {
        std::println("VirtualProtectEx Failed for {} ( Export Name: {} Address: 0x{:X} ). Error Code: 0x{:X}", ModuleName, ExportName, (uintptr_t)FuncAddress, GetLastError());
        return false;
    }

    if (!ReadProcessMemory(ProcessHandle, FuncAddress, Buffer.data(), Buffer.size(), nullptr)) {
        std::println("ReadProcessMemory Failed for {} ( Export Name: {} Address: 0x{:X} ). Error Code: 0x{:X}", ModuleName, ExportName, (uintptr_t)FuncAddress, GetLastError());
        return false;
    }

    if (!VirtualProtectEx(ProcessHandle, FuncAddress, Buffer.size(), OldProtection, &OldProtection)) {
        std::println("VirtualProtectEx (Reverting to old protection) Failed for {} ( Export Name: {} Address: 0x{:X} ). Error Code: 0x{:X}", ModuleName, ExportName, (uintptr_t)FuncAddress, GetLastError());
        return false;
    }

    std::vector<BYTE> CurrentProcessBuffer(25);
    memcpy(CurrentProcessBuffer.data(), FuncAddress, CurrentProcessBuffer.size());
    
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

    if (!ModuleHandle) {
        std::println("GetModuleHandleA Failed for {}. Error Code: 0x{:X}", ModuleName, GetLastError());
        return;
    }

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(ModuleHandle)->e_magic != IMAGE_DOS_SIGNATURE) {
        std::println("Invalid DOS Signature of {}", ModuleName);
        return;
    }

    IMAGE_NT_HEADERS* Header = (IMAGE_NT_HEADERS*)((uintptr_t)ModuleHandle + ((IMAGE_DOS_HEADER*)ModuleHandle)->e_lfanew);

    if (Header->Signature != IMAGE_NT_SIGNATURE) {
        std::println("Invalid NT Signature of {}", ModuleName);
        return;
    }

    if (Header->OptionalHeader.NumberOfRvaAndSizes < 0) {
        std::println("Number of RVA and Sizes is less than 0 of {}", ModuleName);
        return;
    }

    IMAGE_EXPORT_DIRECTORY* Exports = (IMAGE_EXPORT_DIRECTORY*)((uintptr_t)ModuleHandle + Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (Exports->AddressOfNames != 0) {
        DWORD* Names = (DWORD*)((uintptr_t)ModuleHandle + Exports->AddressOfNames);
        for (int i = 0; i <= Exports->NumberOfNames - 1; i++) {
            CheckHooked(ProcessHandle, ModuleName, reinterpret_cast<const char*>(ModuleHandle) + Names[i]);
        }
    }
    else {
        std::println("No exports found in {}", ModuleName);
        return;
    }
}