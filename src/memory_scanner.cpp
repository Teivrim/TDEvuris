#include "memory_scanner.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <algorithm>

std::vector<MemResult> MemoryScanner::scanAll() {
    std::vector<MemResult> results;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) do {
        wchar_t path[MAX_PATH];
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        std::string name;
        if (hProc) {
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
                int l = WideCharToMultiByte(CP_UTF8,0,path,-1,nullptr,0,nullptr,nullptr);
                name.resize(l-1); WideCharToMultiByte(CP_UTF8,0,path,-1,name.data(),l,nullptr,nullptr);
            }
            CloseHandle(hProc);
        }
        if (name.empty()) {
            int l = WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,nullptr,0,nullptr,nullptr);
            name.resize(l-1); WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,name.data(),l,nullptr,nullptr);
        }

        MemResult mr;
        mr.pid = pe.th32ProcessID;
        mr.procName = name;
        bool susp = false;

        if (checkInjection(pe.th32ProcessID, name, mr)) susp = true;
        if (detectHollowing(pe.th32ProcessID, name, mr)) susp = true;

        // Skip benign processes with no findings
        if (susp) results.push_back(mr);

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return results;
}

std::vector<MemResult> MemoryScanner::scanProcess(DWORD pid, const std::string& name) {
    std::vector<MemResult> results;
    MemResult mr;
    mr.pid = pid;
    mr.procName = name;

    bool susp = false;
    if (checkInjection(pid, name, mr)) susp = true;
    if (detectHollowing(pid, name, mr)) susp = true;

    if (susp) results.push_back(mr);
    return results;
}

bool MemoryScanner::checkInjection(DWORD pid, const std::string& name, MemResult& result) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;

    // Check if process has unexpected executable memory that isn't backed by a module
    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = nullptr;
    int suspiciousRegions = 0;

    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == 0) break;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & 0xF0) && // executable (PAGE_EXECUTE*)
            !(mbi.Protect & PAGE_GUARD)) {

            // Check for common shellcode patterns in private executable memory
            std::vector<BYTE> buf(mbi.RegionSize > 4096 ? 4096 : mbi.RegionSize);
            SIZE_T read;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), buf.size(), &read)) {
                // Look for call/push/ret sequences typical of shellcode
                int jmpCount = 0, callCount = 0;
                for (size_t i = 0; i < read - 1; i++) {
                    if (buf[i] == 0xE8) callCount++; // CALL
                    if (buf[i] == 0xE9) jmpCount++;  // JMP
                }
                if (callCount > 5 && jmpCount > 5) {
                    suspiciousRegions++;
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProc);

    if (suspiciousRegions > 2) {
        result.threatName = "Mem.Injection.Shellcode";
        result.category = "trojan";
        result.confidence = 0.6 + (suspiciousRegions * 0.05);
        if (result.confidence > 0.95) result.confidence = 0.95;
        result.suspicious = true;
        return true;
    }
    return false;
}

bool MemoryScanner::detectHollowing(DWORD pid, const std::string& name, MemResult& result) {
    // Check if the process's base address has unexpected characteristics
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;

    wchar_t modPath[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProc, 0, modPath, &sz)) {
        CloseHandle(hProc);
        return false;
    }

    // Read PE header from process memory
    BYTE header[4096];
    SIZE_T read;
    bool hollowed = false;

    if (ReadProcessMemory(hProc, (LPCVOID)0x400000, header, sizeof(header), &read) && read >= 512) {
        // Check MZ signature
        if (header[0] != 'M' || header[1] != 'Z') {
            // Try reading from the actual module base
            HMODULE hMods[1024]; DWORD needed;
            if (EnumProcessModules(hProc, hMods, sizeof(hMods), &needed)) {
                if (needed > 0) {
                    MODULEINFO mi;
                    GetModuleInformation(hProc, hMods[0], &mi, sizeof(mi));
                    if (ReadProcessMemory(hProc, mi.lpBaseOfDll, header, sizeof(header), &read) && read >= 2) {
                        if (header[0] != 'M' || header[1] != 'Z') {
                            hollowed = true; // No PE header at base address
                        }
                    }
                }
            }
        }
    }

    CloseHandle(hProc);

    if (hollowed) {
        result.threatName = "Mem.Hollowing";
        result.category = "rootkit";
        result.confidence = 0.8;
        result.suspicious = true;
        return true;
    }
    return false;
}
