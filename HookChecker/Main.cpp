#include <Windows.h>

#include "Lib.hpp"

#include <iostream>
#include <print>
#include <string>
#include <cstdio>
#include <array>

std::array<const char*, 6> ModulesToCheck = {
"ntdll.dll",
"kernel32.dll",
"user32.dll",
"wintrust.dll",
"crypt32.dll",
"KernelBase.dll"
};

std::string ProcessName;
int main() {
	SetConsoleTitleA("Hook Checker");

	for (int i = 0; i < ModulesToCheck.size(); i++) {
		LoadLibraryA(ModulesToCheck[i]); // windows funnily enough loads some DLLs RIGHT BEFORE we check these modules which causes errors... average windows interaction.
		//std::println("Made sure {} is loaded", ModulesToCheck[i]);
	}

	std::print("Insert Process Name: ");
	std::getline(std::cin, ProcessName);
	std::wstring WideString = std::wstring(ProcessName.begin(), ProcessName.end()); // stupid solution, couldn't find std::getline for wide chars in MSVC.
	std::wprintf(L"ProcessName: %s\n", WideString.c_str());

	HANDLE ProcessHandle = GetProcessHandle(WideString.c_str());

	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE) {
		std::println("GetProcessHandle Failed.");
		return EXIT_FAILURE;
	}

	std::println("");

	for (int i = 0; i < ModulesToCheck.size(); i++) {
		/*
		std::println("Checking {}", ModulesToCheck[i]);
		std::println("");
		*/
		WalkExportsAndCheck(ProcessHandle, ModulesToCheck[i]);
	}

	CloseHandle(ProcessHandle);

	system("pause");
	return EXIT_SUCCESS;
}