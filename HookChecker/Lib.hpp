#include <Windows.h>

#ifndef LIB_H_
#define LIB_H_

HANDLE GetProcessHandle(const wchar_t* ProcessName);
bool CheckHooked(HANDLE ProcessHandle, const char* ModuleName, const char* ExportName);
void WalkExportsAndCheck(HANDLE ProcessHandle, const char* ModuleName);

#endif /* LIB_H_ */