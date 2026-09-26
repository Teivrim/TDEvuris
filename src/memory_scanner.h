#pragma once
// NOMINMAX: без этого windows.h определяет min/max как макросы,
// и любой вызов std::min/std::max не компилируется (MSVC C2589).
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>
#include <vector>

struct MemResult {
    DWORD pid;
    std::string procName;
    std::string threatName;
    std::string category;
    double confidence = 0.0;
    bool suspicious = false;
};

class MemoryScanner {
public:
    std::vector<MemResult> scanAll();
    std::vector<MemResult> scanProcess(DWORD pid, const std::string& name);

private:
    bool checkInjection(DWORD pid, const std::string& name, MemResult& result);
    bool detectHollowing(DWORD pid, const std::string& name, MemResult& result);
};
