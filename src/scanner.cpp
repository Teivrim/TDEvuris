#include "scanner.h"
#include "hasher.h"
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <windows.h>
#include <securitybaseapi.h>
#include <tlhelp32.h>

Scanner::Scanner(const SignatureDB& sigdb) : m_sigdb(sigdb) {}

bool Scanner::isAdmin() {
    BOOL admin = FALSE;
    PSID group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0, &group)) {
        CheckTokenMembership(nullptr, group, &admin);
        FreeSid(group);
    }
    return admin == TRUE;
}

static std::string wstrToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), len, nullptr, nullptr);
    return s;
}

static std::wstring utf8ToWstr(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), len);
    return w;
}

static bool isDir(const WIN32_FIND_DATAW& d) {
    return (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static bool isReparse(const WIN32_FIND_DATAW& d) {
    return (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

static bool skipDir(const std::wstring& name) {
    return name == L"$Recycle.Bin" || name == L"System Volume Information" ||
           name == L"$RECYCLE.BIN" || name == L"Config.Msi" || name == L"Recovery" ||
           name == L"Windows.old";
}

// --- Recursive walk with explicit stack (DFS) ---
static void walk(const std::wstring& root, int maxDepth,
                 const std::function<void(const std::wstring&, bool, int)>& cb)
{
    std::vector<std::pair<std::wstring, int>> stack;
    stack.push_back({root, 0});

    while (!stack.empty()) {
        auto [dir, depth] = stack.back();
        stack.pop_back();

        if (depth > maxDepth) continue;

        std::wstring search = dir + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(search.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;

        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;

            std::wstring full = dir + L"\\" + name;
            bool directory = isDir(fd);

            cb(full, directory, depth);

            if (directory && !isReparse(fd) && depth < maxDepth && !skipDir(name))
                stack.push_back({full, depth + 1});
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

// --- Pre-count (same walk, just counts) ---
struct CountCtx { int total = 0; };

static void countFiles(const std::wstring& root, int maxDepth, CountCtx& ctx) {
    walk(root, maxDepth, [&](const std::wstring&, bool dir, int) {
        if (!dir) ctx.total++;
    });
}

// --- Scan single file ---
ScanResult Scanner::scanFile(const std::string& filepath) {
    ScanResult result;
    result.filepath = filepath;

    try {
        std::string hash = Hasher::sha256(filepath);
        if (hash.empty()) {
            result.status = Error;
            result.description = "cannot read";
            return result;
        }

        auto sig = m_sigdb.match(hash);
        if (sig) {
            result.status      = SignatureMatch;
            result.threatName  = sig->name;
            result.category    = sig->category;
            result.description = sig->description;
            result.confidence  = 1.0;
            return result;
        }

        auto heur = m_heur.analyze(filepath);
        if (!heur.empty()) {
            result.status      = HeuristicMatch;
            result.threatName  = heur[0].name;
            result.category    = heur[0].category;
            result.description = "Heuristic";
            result.confidence  = heur[0].confidence;
        }
    } catch (const std::exception& e) {
        result.status = Error;
        result.description = e.what();
    }
    return result;
}

// --- Scan directory ---
ScanSummary Scanner::scanDirectory(const std::string& dirpath,
                                   const ProgressCb& onProgress,
                                   const ResultCb& onResult)
{
    ScanSummary summary;
    summary.admin = isAdmin();
    m_stopped = false;

    std::wstring root = utf8ToWstr(dirpath);
    int maxDepth = 30;

    // Pre-count
    CountCtx countCtx;
    countFiles(root, maxDepth, countCtx);
    summary.totalFiles = countCtx.total;

    // Scan
    int scanned = 0;
    walk(root, maxDepth, [&](const std::wstring& path, bool dir, int) {
        if (m_stopped) return;
        if (dir) return;

        std::string upath = wstrToUtf8(path);
        auto result = scanFile(upath);
        scanned++;

        if (onProgress)
            onProgress(upath, scanned, summary.totalFiles, summary.skippedAccess, "");

        if (result.status != Clean && onResult)
            onResult(result);

        switch (result.status) {
            case Clean:          summary.clean++;     break;
            case SignatureMatch: summary.infected++;  break;
            case HeuristicMatch: summary.heuristic++; break;
            case Error:          summary.errors++;    break;
        }
    });

    summary.scannedFiles = scanned;
    return summary;
}

// --- Scan processes ---
ScanSummary Scanner::scanProcesses(const ProgressCb& onProgress,
                                    const ResultCb& onResult)
{
    ScanSummary summary;
    summary.admin = isAdmin();
    m_stopped = false;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return summary;

    // First pass: count
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    int total = 0;
    std::vector<DWORD> pids;
    if (Process32FirstW(snap, &pe)) {
        do { total++; pids.push_back(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
    }
    summary.totalFiles = total;
    int scanned = 0;

    // Second pass: scan
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (m_stopped) break;
            scanned++;

            wchar_t path[MAX_PATH];
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            std::string upath;
            if (hProc) {
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, path, &sz))
                    upath = wstrToUtf8(path);
                CloseHandle(hProc);
            }

            if (upath.empty())
                upath = wstrToUtf8(std::wstring(L"PID:") + std::to_wstring(pe.th32ProcessID) + L" " + pe.szExeFile);

            auto result = scanFile(upath.empty() ? wstrToUtf8(pe.szExeFile) : upath);
            result.filepath = wstrToUtf8(std::wstring(L"[PID ") + std::to_wstring(pe.th32ProcessID) + L"] ") + result.filepath;

            if (onProgress)
                onProgress(upath, scanned, total, 0, "");

            if (result.status != Clean && onResult)
                onResult(result);

            switch (result.status) {
                case Clean:          summary.clean++;     break;
                case SignatureMatch: summary.infected++;  break;
                case HeuristicMatch: summary.heuristic++; break;
                case Error:          summary.errors++;    break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    summary.scannedFiles = scanned;
    return summary;
}

void Scanner::stop() { m_stopped = true; }
