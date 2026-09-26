#include "registry_scanner.h"
#include <windows.h>
#include <string>
#include <vector>

static std::string w2s(const std::wstring& w) {
    if (w.empty()) return {};
    int l = WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(),nullptr,0,nullptr,nullptr);
    std::string s(l,0); WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(),s.data(),l,nullptr,nullptr);
    return s;
}

static void enumKey(HKEY root, const std::wstring& sub, std::vector<RegEntry>& out, const std::string& cat) {
    HKEY hKey;
    if (RegOpenKeyExW(root, sub.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t name[4096], data[4096];
    DWORD nameSz, dataSz, type;

    while (true) {
        nameSz = 4096; dataSz = 4096; type = 0;
        LONG ret = RegEnumValueW(hKey, idx++, name, &nameSz, nullptr, &type,
                                  (LPBYTE)data, &dataSz);
        if (ret != ERROR_SUCCESS) break;

        std::wstring valName(name, nameSz);
        std::wstring valData;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            valData.assign(data, dataSz / sizeof(wchar_t));
            if (!valData.empty() && valData.back() == L'\0') valData.pop_back();
        } else if (type == REG_DWORD) {
            valData = L"DWORD:" + std::to_wstring(*(DWORD*)data);
        } else {
            valData = L"(binary)";
        }

        RegEntry e;
        e.key = w2s(sub);
        e.value = w2s(valName);
        e.data = w2s(valData);
        e.category = cat;
        out.push_back(e);
    }
    RegCloseKey(hKey);
}

std::vector<RegEntry> RegistryScanner::enumAutoruns() {
    std::vector<RegEntry> results;

    // User autoruns
    enumKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", results, "autorun");
    enumKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", results, "autorun");
    // System autoruns
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", results, "autorun");
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", results, "autorun");
    // Winlogon
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", results, "autorun");
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", results, "autorun");
    // Browser helper objects
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", results, "bho");
    // ActiveX / Shell execute hooks
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", results, "shell_hook");
    // AppInit DLLs
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", results, "appinit");
    // Boot execute
    enumKey(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\BootExecute", results, "boot");
    // Image hijacks
    enumKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", results, "image_hijack");
    // Services
    enumKey(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", results, "service");

    return results;
}

static bool isSuspiciousPath(const std::string& path) {
    std::string low;
    for (auto c : path) low += std::tolower((unsigned char)c);
    if (low.find("temp") != std::string::npos) return true;
    if (low.find("appdata\\local\\temp") != std::string::npos) return true;
    if (low.find("users\\") != std::string::npos && low.find("appdata\\roaming") != std::string::npos) {
        if (low.find("microsoft") == std::string::npos) return true;
    }
    if (low.find("\\downloads\\") != std::string::npos) return true;
    return false;
}

static bool isSuspiciousName(const std::string& name) {
    std::string low;
    for (auto c : name) low += std::tolower((unsigned char)c);
    if (low.find("svchost") != std::string::npos && low != "svchost.exe") return true;
    if (low.find("rundll32") != std::string::npos && low != "rundll32.exe") return true;
    if (low.find("explorer") != std::string::npos && low != "explorer.exe") return true;
    if (low.find("iexplore") != std::string::npos && low != "iexplore.exe") return true;
    return false;
}

std::vector<RegResult> RegistryScanner::analyze() {
    std::vector<RegResult> results;
    auto entries = enumAutoruns();

    for (auto& e : entries) {
        RegResult rr;
        rr.entry = e;

        if (isSuspiciousPath(e.data)) {
            rr.threatName = "Reg.Autorun.SuspiciousPath";
            rr.threatCategory = "trojan";
            rr.confidence = 0.6;
            rr.suspicious = true;
        }
        if (isSuspiciousName(e.value)) {
            rr.threatName = "Reg.Autorun.SuspiciousName";
            rr.threatCategory = "rootkit";
            rr.confidence = 0.7;
            rr.suspicious = true;
        }
        if (e.key.find("ImageHijack") != std::string::npos) {
            rr.threatName = "Reg.ImageHijack." + e.value;
            rr.threatCategory = "rootkit";
            rr.confidence = 0.8;
            rr.suspicious = true;
        }
        if (e.data.find(".vbs") != std::string::npos || e.data.find(".ps1") != std::string::npos ||
            e.data.find(".js") != std::string::npos || e.data.find(".hta") != std::string::npos) {
            rr.threatName = "Reg.Autorun.ScriptInRun";
            rr.threatCategory = "script";
            rr.confidence = 0.5;
            rr.suspicious = true;
        }

        if (rr.suspicious)
            results.push_back(rr);
    }
    return results;
}
