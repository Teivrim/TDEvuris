#include "heuristics.h"
#include <fstream>
#include <vector>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <cstring>
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wchar.h>

static std::string toLower(std::string s) {
    for (auto& c : s) c = std::tolower(static_cast<unsigned char>(c));
    return s;
}

static std::string getExt(const std::string& p) {
    auto idx = p.rfind('.');
    if (idx == std::string::npos) return {};
    return toLower(p.substr(idx));
}

static double computeEntropy(const uint8_t* data, size_t len) {
    if (!len) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / len;
        e -= p * std::log2(p);
    }
    return e;
}

struct PEInfo {
    bool valid = false;
    uint16_t machine = 0;
    uint16_t numSections = 0;
    uint32_t sectionTableOff = 0;
    std::vector<char> buf;
    size_t bufSize = 0;

    static PEInfo read(const std::string& path) {
        PEInfo info;
        std::ifstream f(path, std::ios::binary);
        if (!f) return info;

        std::vector<char> b(1024 * 64);
        f.read(b.data(), b.size());
        info.bufSize = (size_t)f.gcount();
        f.close();

        if (info.bufSize < 2 || b[0] != 'M' || b[1] != 'Z') return info;
        if (info.bufSize < 0x3C + 4) return info;

        uint32_t peOff;
        memcpy(&peOff, b.data() + 0x3C, 4);
        if (peOff + 24 > info.bufSize) return info;

        if (b[peOff] != 'P' || b[peOff + 1] != 'E') return info;

        memcpy(&info.machine, b.data() + peOff + 4, 2);
        memcpy(&info.numSections, b.data() + peOff + 6, 2);

        uint16_t optHdrSize;
        memcpy(&optHdrSize, b.data() + peOff + 20, 2);

        info.sectionTableOff = peOff + 24 + optHdrSize;
        info.valid = true;
        info.buf = std::move(b);
        return info;
    }

    std::string sectionName(int idx) const {
        size_t off = sectionTableOff + idx * 40;
        if (off + 8 > bufSize) return "";
        char n[9] = {}; memcpy(n, buf.data() + off, 8); return n;
    }

    uint32_t sectionChars(int idx) const {
        size_t off = sectionTableOff + idx * 40 + 36;
        if (off + 4 > bufSize) return 0;
        uint32_t c; memcpy(&c, buf.data() + off, 4); return c;
    }
};

static bool hasSuspiciousAPIs(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::vector<char> buf(512 * 1024);
    f.read(buf.data(), buf.size());
    auto sz = (size_t)f.gcount();
    f.close();

    if (sz < 4) return false;

    // Search for known suspicious API strings in the import section
    static const char* apis[] = {
        "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
        "VirtualProtectEx", "SetWindowsHookEx", "GetProcAddress",
        "LoadLibraryA", "LoadLibraryW", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "InternetOpenA", "socket", "connect",
        "send", "recv", "RegSetValue", "CreateService",
        "StartService", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "MiniDumpWriteDump", "CryptEncrypt", "CryptDecrypt"
    };

    auto ci = [](char a, char b) { return tolower(a) == tolower(b); };
    int suspiciousCount = 0;
    for (auto* api : apis) {
        size_t alen = strlen(api);
        for (size_t i = 0; i + alen <= sz; i++) {
            bool match = true;
            for (size_t j = 0; j < alen; j++) {
                if (!ci(buf[i + j], api[j])) { match = false; break; }
            }
            if (match) { suspiciousCount++; break; }
        }
    }
    return suspiciousCount >= 3;
}

static bool hasEmbeddedURL(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::vector<char> buf(256 * 1024);
    f.read(buf.data(), buf.size());
    auto sz = (size_t)f.gcount();
    f.close();

    std::string_view sv(buf.data(), sz);
    // Check for http://, https://, ftp://, hxxp://
    int count = 0;
    size_t pos = 0;
    while ((pos = sv.find("http", pos)) != std::string_view::npos) {
        count++;
        pos += 4;
    }
    pos = 0;
    while ((pos = sv.find("ftp:", pos)) != std::string_view::npos) {
        count++;
        pos += 4;
    }
    pos = 0;
    while ((pos = sv.find("hxxp", pos)) != std::string_view::npos) {
        count++;
        pos += 4;
    }
    return count >= 2;
}

static bool isDigitallySigned(const std::string& path) {
#ifdef _WIN32
    WINTRUST_FILE_INFO wfi = {};
    wfi.cbStruct = sizeof(wfi);
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.data(), (int)path.size(), nullptr, 0);
    std::wstring wpath(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.data(), (int)path.size(), wpath.data(), wlen);
    wfi.pcwszFilePath = wpath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &wfi;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG res = WinVerifyTrust(nullptr, &action, &wtd);
    return res == 0;
#else
    return false;
#endif
}

static bool hasRansomwareStrings(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::vector<char> buf(256 * 1024);
    f.read(buf.data(), buf.size());
    auto sz = (size_t)f.gcount();
    f.close();

    static const char* patterns[] = {
        "your files", "bitcoin", "btc address", "ransom", "decrypt",
        "pay .* bitcoin", "wallet", "encrypted", "recover your files",
        ".onion", "contact us", "send .* to", "unlock"
    };

    auto ci = [](char a, char b) { return tolower(a) == tolower(b); };
    int count = 0;
    for (auto* pat : patterns) {
        size_t alen = strlen(pat);
        for (size_t i = 0; i + alen <= sz; i++) {
            bool match = true;
            for (size_t j = 0; j < alen; j++) {
                if (pat[j] == ' ') continue;
                if (!ci(buf[i + j], pat[j])) { match = false; break; }
            }
            if (match) { count++; break; }
        }
    }
    return count >= 3;
}

static bool readFirstBytes(const std::string& path, unsigned char* out, size_t n) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.read((char*)out, n);
    f.close();
    return true;
}

std::vector<HeuristicResult> HeuristicsEngine::analyze(const std::string& filepath) {
    std::vector<HeuristicResult> results;

    try {
        auto ext = getExt(filepath);
        auto fsize = std::filesystem::file_size(filepath);

        // Autorun.inf check (common USB worm dropper)
        if (ext == ".inf") {
            std::ifstream f(filepath);
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            std::string low = toLower(content);
            if (low.find("autorun") != std::string::npos && low.find("shell") != std::string::npos &&
                low.find("open") != std::string::npos) {
                results.push_back({"Heuristic.Autorun.Worm", "worm", 0.8});
            }
        }

        // Ransomware note text files
        if (ext == ".txt" && fsize < 200 * 1024) {
            if (hasRansomwareStrings(filepath)) {
                results.push_back({"Heuristic.Ransomware.Note", "ransomware", 0.85});
            }
        }

        // Office documents with VBA macros (OLE compound file magic)
        if (ext == ".doc" || ext == ".docm" || ext == ".xls" || ext == ".xlsm" ||
            ext == ".ppt" || ext == ".pptm" || ext == ".dotm" || ext == ".xlam" ||
            ext == ".rtf") {
            unsigned char magic[8];
            if (readFirstBytes(filepath, magic, 8)) {
                // OLE2 compound file: D0 CF 11 E0 A1 B1 1A E1
                if (magic[0]==0xD0 && magic[1]==0xCF && magic[2]==0x11 && magic[3]==0xE0) {
                    std::ifstream f(filepath, std::ios::binary);
                    std::vector<char> buf(64 * 1024);
                    f.read(buf.data(), buf.size());
                    auto sz = (size_t)f.gcount();
                    f.close();
                    // "Auto_Open", "ThisDocument", "VBA" indicators
                    std::string data(buf.data(), sz);
                    std::string low = toLower(data);
                    if (low.find("vba") != std::string::npos ||
                        low.find("auto_open") != std::string::npos ||
                        low.find("workbook_open") != std::string::npos) {
                        results.push_back({"Heuristic.Office.MacroEnabled", "macro", 0.6});
                        // Check for known bad macro API calls
                        if (low.find("createshell") != std::string::npos ||
                            low.find("adodb") != std::string::npos ||
                            low.find("wscript") != std::string::npos ||
                            low.find("powershell") != std::string::npos) {
                            results.push_back({"Heuristic.Office.MaliciousMacro", "trojan", 0.85});
                        }
                    }
                }
            }
        }

        // ISO / disk image files often used to bypass MOTW
        if (ext == ".iso" || ext == ".img" || ext == ".vhd" || ext == ".vhdx") {
            results.push_back({"Heuristic.File.DiskImage", "suspicious", 0.3});
        }

        if (ext == ".exe" || ext == ".dll" || ext == ".scr" ||
            ext == ".sys" || ext == ".com" || ext == ".pif" ||
            ext == ".msi" || ext == ".vbs" || ext == ".ps1" ||
            ext == ".bat" || ext == ".cmd" || ext == ".js" ||
            ext == ".wsf" || ext == ".hta" || ext == ".jar") {

            // Script-based threats
            if (ext == ".vbs" || ext == ".ps1" || ext == ".js" ||
                ext == ".bat" || ext == ".cmd" || ext == ".hta" || ext == ".wsf") {
                results.push_back({"Heuristic.Script.ExecutableScript", "script", 0.4});

                // Check for embedded URLs in scripts
                if (hasEmbeddedURL(filepath)) {
                    results.push_back({"Heuristic.Script.EmbeddedURL", "downloader", 0.7});
                }
            }

            // PE analysis
            auto pe = PEInfo::read(filepath);
            if (pe.valid) {
                // Check sections
                bool hasWX = false;
                bool hasPacked = false;
                bool hasAbnormalName = false;
                for (uint16_t i = 0; i < pe.numSections; i++) {
                    auto name = toLower(pe.sectionName(i));
                    auto chars = pe.sectionChars(i);
                    bool write = (chars & 0x80000000) != 0;
                    bool exec  = (chars & 0x20000000) != 0;

                    if (write && exec) hasWX = true;

                    if (name == ".upx" || name == ".pack" || name == ".zlib" ||
                        name == ".lzma" || name == ".mpress" || name == ".nsp0" ||
                        name == ".nsp1" || name == ".nsp2" || name == ".themida" ||
                        name == ".vmp0" || name == ".vmp1" || name == ".vmp2" ||
                        name == ".enigma" || name == ".armadillo") {
                        hasPacked = true;
                    }

                    if (name.size() > 0 && name[0] == '.' && name != ".text" &&
                        name != ".data" && name != ".rdata" && name != ".bss" &&
                        name != ".idata" && name != ".edata" && name != ".pdata" &&
                        name != ".rsrc" && name != ".reloc" && name != ".tls" &&
                        name != ".crt" && !hasPacked) {
                        if (name.find("pack") != std::string::npos ||
                            name.find("encrypt") != std::string::npos) {
                            hasPacked = true;
                        }
                    }
                }

                if (hasPacked) {
                    results.push_back({"Heuristic.PE.PackedBinary", "packed", 0.7});
                }
                if (hasWX) {
                    results.push_back({"Heuristic.PE.WritableExecutable", "suspicious", 0.5});
                }

                // Check suspicious APIs
                if (hasSuspiciousAPIs(filepath)) {
                    results.push_back({"Heuristic.PE.SuspiciousAPIs", "trojan", 0.6});
                }

                // Check embedded URLs
                if (hasEmbeddedURL(filepath)) {
                    results.push_back({"Heuristic.PE.EmbeddedURL", "downloader", 0.6});
                }

                // Check digital signature on EXEs (only flag if missing)
                if (ext == ".exe" || ext == ".dll") {
                    if (!isDigitallySigned(filepath) && fsize > 10240) {
                        results.push_back({"Heuristic.PE.Unsigned", "suspicious", 0.2});
                    }
                }

                // Entropy analysis on first 64KB
                size_t entLen = std::min(pe.bufSize, size_t(65536));
                double ent = computeEntropy((uint8_t*)pe.buf.data(), entLen);
                if (ent > 7.2) {
                    results.push_back({"Heuristic.PE.HighEntropy", "packed", 0.5});
                }
                if (ent > 7.7) {
                    results.push_back({"Heuristic.PE.VeryHighEntropy", "packed", 0.7});
                }
            }
        }

        // Double extension check
        auto base = std::filesystem::path(filepath).filename().string();
        auto dotPos = base.find('.');
        if (dotPos != std::string::npos && base.find('.', dotPos + 1) != std::string::npos) {
            results.push_back({"Heuristic.File.DoubleExtension", "social", 0.5});
        }

        // Suspiciously small executable
        if (fsize < 4096 && (ext == ".exe" || ext == ".scr" || ext == ".com")) {
            results.push_back({"Heuristic.File.TooSmallForExe", "suspicious", 0.4});
        }

        // Large executable from unknown origin (no signature)
        if (fsize > 100 * 1024 * 1024 && ext == ".exe") {
            results.push_back({"Heuristic.File.SuspiciouslyLarge", "suspicious", 0.3});
        }

        // Check for hidden attribute (only non-system)
        DWORD winAttr = GetFileAttributesA(filepath.c_str());
        if (winAttr != INVALID_FILE_ATTRIBUTES && (winAttr & FILE_ATTRIBUTE_HIDDEN)) {
            auto fn = std::filesystem::path(filepath).filename().string();
            if (fn != "desktop.ini" && fn != "thumbs.db" && ext == ".exe") {
                results.push_back({"Heuristic.File.HiddenExecutable", "stealth", 0.6});
            }
        }

    } catch (...) {
    }

    return results;
}
