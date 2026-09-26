#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <dbt.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <thread>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <filesystem>

#include "scanner.h"
#include "signatures.h"
#include "hasher.h"
#include "network_scanner.h"
#include "registry_scanner.h"
#include "boot_scanner.h"
#include "memory_scanner.h"
#include "shredder.h"
#include "watcher.h"
#include "updater.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winmm.lib")

#define WM_SCAN_PROGRESS  (WM_USER + 1)
#define WM_SCAN_RESULT    (WM_USER + 2)
#define WM_SCAN_DONE      (WM_USER + 3)
#define WM_TRAY_ICON      (WM_USER + 4)
#define WM_DASH_UPDATE    (WM_USER + 5)
#define WM_WATCHER_EVENT  (WM_USER + 6)
#define WM_USB_ARRIVAL    (WM_USER + 7)
#define WM_UPDATE_DONE    (WM_USER + 8)
#define WM_QUARANTINED    (WM_USER + 9)

enum Ctrl {
    ID_TAB = 1001, ID_SCAN_BTN, ID_STOP_BTN, ID_CLEAR_BTN, ID_LOG_BTN,
    ID_DRIVE_COMBO, ID_RESULT_LIST, ID_PROGRESS, ID_ADMIN_LBL,
    ID_STATS_TOTAL, ID_STATS_CLEAN, ID_STATS_INFECT, ID_STATS_HEUR, ID_STATS_ERROR, ID_STATS_SKIP,
    ID_QUAR_LIST, ID_QUAR_RESTORE_BTN, ID_QUAR_DELETE_BTN, ID_QUAR_SELECTALL_BTN, ID_QUAR_EMPTY_BTN,
    ID_SCANPROC_BTN, ID_SCANNET_BTN, ID_SCANREG_BTN, ID_EXPORT_BTN, ID_PROFILE_COMBO,
    ID_QUICKSCAN_BTN, ID_FULLSCAN_BTN,
    ID_SETT_SIG_COUNT, ID_SETT_HEUR_TOGGLE, ID_SETT_RTP_TOGGLE,
    ID_SETT_STARTUP_TOGGLE, ID_SETT_TRAY_TOGGLE,
    ID_SETT_EXCL_LIST, ID_SETT_EXCL_ADD, ID_SETT_EXCL_REMOVE,
    ID_SCANBOOT_BTN, ID_SCANMEM_BTN, ID_SHRED_BTN,
    ID_SCHEDULE_COMBO, ID_SCHEDULE_TOGGLE,
    ID_RTP_STATUS,
    ID_HTMLREPORT_BTN,
    ID_UPDATE_BTN, ID_ABOUT_BTN, ID_CONN_LIST_BTN,
    ID_TOOLS_PROC_LIST, ID_TOOLS_PROC_REFRESH, ID_TOOLS_PROC_KILL,
    ID_TOOLS_STARTUP_LIST, ID_TOOLS_STARTUP_REFRESH, ID_TOOLS_STARTUP_DISABLE,
    ID_TRAY_ICON,
};

static HWND g_hToolsPanel;
static HWND g_hProcList, g_hStartupList;
static std::vector<std::pair<std::string, DWORD>> g_procEntries;
static std::vector<std::wstring> g_startupEntries;

static HINSTANCE g_hInst = nullptr;
static HWND g_hWnd, g_hTab, g_hDashPanel, g_hScanPanel, g_hQuarPanel, g_hSetPanel, g_hRtpLbl;
static HWND g_hDriveCombo, g_hScanBtn, g_hStopBtn, g_hClearBtn, g_hLogBtn;
static HWND g_hList, g_hProgress, g_hStatus, g_hAdminLbl;
static HWND g_hStats[6];
static HWND g_hQuarList, g_hQuarRestore, g_hQuarDelete, g_hQuarSelectAll, g_hQuarEmpty;
static HWND g_hSetSigCount, g_hSetHeur, g_hSetStartup, g_hSetTray;
static HWND g_hSetExclList, g_hSetExclAdd, g_hSetExclRemove;
static HWND g_hDashStatus, g_hDashLastScan, g_hDashSigs, g_hDashThreats;

static SignatureDB g_sigdb;
static Scanner* g_scanner = nullptr;
static std::thread g_scanThread;
static bool g_scanning = false;
static int g_totalFiles = 0, g_scannedFiles = 0, g_skippedFiles = 0;
static int g_countTotal = 0, g_countClean = 0, g_countInfected = 0;
static int g_countHeuristic = 0, g_countErrors = 0;
static int g_itemCounter = 0;
static std::string g_exeDir;
static std::wstring g_logPath;
static std::ofstream g_logFile;
static CRITICAL_SECTION g_logCs;
static std::vector<std::wstring> g_exclusions;
static std::wstring g_lastScanTime = L"Never";
static bool g_minimizeToTray = false;
static bool g_rtpEnabled = false;
static FileWatcher g_watcher;
static UINT_PTR g_scheduleTimer = 0;
static std::wstring g_lastUsbScanned;

static int g_sortCol = 0;
static bool g_sortAsc = true;

static const COLORREF CLR_BG      = RGB(20, 20, 24);
static const COLORREF CLR_PANEL   = RGB(30, 30, 36);
static const COLORREF CLR_CLEAN   = RGB(70, 210, 70);
static const COLORREF CLR_INF_BG  = RGB(55, 14, 14);
static const COLORREF CLR_INF_FG  = RGB(255, 60, 60);
static const COLORREF CLR_HEU_BG  = RGB(55, 34, 6);
static const COLORREF CLR_HEU_FG  = RGB(255, 180, 40);
static const COLORREF CLR_ERR_FG  = RGB(130, 130, 130);
static const COLORREF CLR_TEXT    = RGB(215, 215, 215);
static const COLORREF CLR_ACCENT  = RGB(0, 140, 255);
static const COLORREF CLR_CARD    = RGB(35, 35, 42);
static const COLORREF CLR_GREEN   = RGB(50, 200, 80);
static const COLORREF CLR_YELLOW  = RGB(230, 200, 40);

static HFONT g_hFont = nullptr, g_hFontBold = nullptr, g_hFontLarge = nullptr;
static HBRUSH g_hBrBg = nullptr, g_hBrPanel = nullptr, g_hBrCard = nullptr;

static std::string ws2s(const std::wstring& w) {
    if (w.empty()) return {};
    int l = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr,0, nullptr, nullptr);
    std::string s(l,0); WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(), s.data(),l, nullptr, nullptr);
    return s;
}
static std::wstring s2ws(const std::string& s) {
    if (s.empty()) return {};
    int l = MultiByteToWideChar(CP_UTF8,0, s.data(), (int)s.size(), nullptr,0);
    std::wstring w(l,0); MultiByteToWideChar(CP_UTF8,0, s.data(), (int)s.size(), w.data(),l);
    return w;
}
static std::wstring ts() {
    auto n = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm t; localtime_s(&t, &n);
    wchar_t b[20]; wcsftime(b,20,L"%H:%M:%S",&t); return b;
}
static std::wstring tds() {
    auto n = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm t; localtime_s(&t, &n);
    wchar_t b[64]; wcsftime(b,64,L"%Y-%m-%d %H:%M:%S",&t); return b;
}

static void enableScanCtrls(bool scanning) {
    EnableWindow(g_hScanBtn, !scanning);
    EnableWindow(g_hStopBtn, scanning);
    EnableWindow(g_hDriveCombo, !scanning);
}

static void conout(const std::wstring& s) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h!=INVALID_HANDLE_VALUE) { DWORD w; WriteConsoleW(h,s.data(),(DWORD)s.size(),&w,nullptr); }
}
static void logline(const std::wstring& line) {
    auto t = ts();
    EnterCriticalSection(&g_logCs);
    if (g_logFile.is_open()) g_logFile << ws2s(t + L" " + line) << std::endl;
    LeaveCriticalSection(&g_logCs);
    conout(t + L" " + line + L"\n");
}
static void openLog() {
    if (g_logFile.is_open()) g_logFile.close();
    auto n = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm t; localtime_s(&t, &n);
    wchar_t b[64]; wcsftime(b,64,L"scan_log_%Y%m%d_%H%M%S.txt",&t);
    g_logPath = s2ws(g_exeDir) + L"\\" + b;
    g_logFile.open(g_logPath.c_str());
}
static void updateStats() {
    auto s = [](HWND h, const std::wstring& t) { SetWindowTextW(h, t.c_str()); };
    s(g_hStats[0], L"  Files: "   + std::to_wstring(g_countTotal));
    s(g_hStats[1], L"  Clean: "   + std::to_wstring(g_countClean));
    s(g_hStats[2], L"  Infected: "+ std::to_wstring(g_countInfected));
    s(g_hStats[3], L"  Heuristic: "+ std::to_wstring(g_countHeuristic));
    s(g_hStats[4], L"  Errors: "  + std::to_wstring(g_countErrors));
    s(g_hStats[5], L"  Skipped: " + std::to_wstring(g_skippedFiles));
}

static void loadExclusions() {
    g_exclusions.clear();
    std::ifstream f((s2ws(g_exeDir) + L"\\exclusions.txt").c_str());
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) g_exclusions.push_back(s2ws(line));
    }
}
static void saveExclusions() {
    std::ofstream f((s2ws(g_exeDir) + L"\\exclusions.txt").c_str());
    for (auto& e : g_exclusions) f << ws2s(e) << std::endl;
}
static void refreshExclList() {
    if (!g_hSetExclList) return;
    SendMessageW(g_hSetExclList, LB_RESETCONTENT, 0, 0);
    for (auto& e : g_exclusions)
        SendMessageW(g_hSetExclList, LB_ADDSTRING, 0, (LPARAM)e.c_str());
}

static bool isExcluded(const std::wstring& path) {
    for (auto& e : g_exclusions)
        if (path.find(e) != std::wstring::npos) return true;
    return false;
}

// === Sort ===
struct SortItem { int idx; ScanStatus status; std::wstring cols[5]; };
static std::vector<SortItem> g_sortItems;

static int CALLBACK SortCB(LPARAM a, LPARAM b, LPARAM) {
    auto& ia = g_sortItems[(int)a];
    auto& ib = g_sortItems[(int)b];
    if (g_sortCol == 1) {
        int sa = (int)ia.status, sb = (int)ib.status;
        return g_sortAsc ? sa - sb : sb - sa;
    }
    int r = ia.cols[g_sortCol].compare(ib.cols[g_sortCol]);
    return g_sortAsc ? r : -r;
}

static void addResult(const ScanResult& result) {
    g_countTotal++;
    int idx = g_itemCounter++;
    SortItem si;
    si.idx = idx; si.status = result.status;
    si.cols[0] = s2ws(result.filepath);
    LVITEMW lv = {}; lv.mask = LVIF_TEXT|LVIF_PARAM; lv.iItem = idx; lv.lParam = (LPARAM)result.status;
    lv.iSubItem = 0; lv.pszText = const_cast<wchar_t*>(si.cols[0].c_str()); ListView_InsertItem(g_hList, &lv);
    static const wchar_t* sts[] = {L"CLEAN",L"INFECTED",L"HEURISTIC",L"ERROR"};
    si.cols[1] = (size_t)result.status<4 ? sts[result.status] : L"?";
    ListView_SetItemText(g_hList, idx, 1, const_cast<wchar_t*>(si.cols[1].c_str()));
    si.cols[2] = s2ws(result.category.empty() ? "-" : result.category);
    ListView_SetItemText(g_hList, idx, 2, const_cast<wchar_t*>(si.cols[2].c_str()));
    si.cols[3] = s2ws(result.threatName.empty() ? "-" : result.threatName);
    ListView_SetItemText(g_hList, idx, 3, const_cast<wchar_t*>(si.cols[3].c_str()));
    wchar_t c[16]; swprintf(c,16,L"%.0f%%",result.confidence*100);
    si.cols[4] = c; ListView_SetItemText(g_hList, idx, 4, c);
    g_sortItems.push_back(si);
    switch (result.status) {
        case Clean: g_countClean++; break;
        case SignatureMatch: g_countInfected++; break;
        case HeuristicMatch: g_countHeuristic++; break;
        case Error: g_countErrors++; break;
    }
    updateStats();
    if (result.status != Clean) {
        logline(L"[" + si.cols[1] + L"][" + si.cols[2] + L"] " + si.cols[3] + L"  " + si.cols[0]);
        if (result.status == SignatureMatch) MessageBeep(MB_ICONHAND);
    }
}

static void scanThread(std::wstring rootW) {
    auto prog = [&](const std::string& f, int s, int t, int sk, const std::string&) {
        g_scannedFiles = s; g_totalFiles = t; g_skippedFiles = sk;
        PostMessageW(g_hWnd, WM_SCAN_PROGRESS, (WPARAM)s, (LPARAM)t);
    };
    auto res = [&](const ScanResult& r) {
        if (isExcluded(s2ws(r.filepath))) return;
        PostMessageW(g_hWnd, WM_SCAN_RESULT, 0, (LPARAM)new ScanResult(r));
    };
    auto dir = ws2s(rootW);
    g_scanner = new Scanner(g_sigdb);
    auto sum = g_scanner->scanDirectory(dir, prog, res);
    PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary(sum));
}

static LRESULT CDraw(LPARAM lp) {
    auto* cd = (NMLVCUSTOMDRAW*)lp;
    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
    if (cd->nmcd.dwDrawStage != CDDS_ITEMPREPAINT) return CDRF_DODEFAULT;
    switch ((ScanStatus)cd->nmcd.lItemlParam) {
        case Clean:          cd->clrText = CLR_CLEAN;  cd->clrTextBk = CLR_BG; break;
        case SignatureMatch: cd->clrText = CLR_INF_FG; cd->clrTextBk = CLR_INF_BG; break;
        case HeuristicMatch: cd->clrText = CLR_HEU_FG; cd->clrTextBk = CLR_HEU_BG; break;
        case Error:          cd->clrText = CLR_ERR_FG; cd->clrTextBk = CLR_BG; break;
    }
    return CDRF_NEWFONT;
}

static void showThreatDetails(HWND hList, int sel) {
    wchar_t cols[5][4096];
    for (int i = 0; i < 5; i++) {
        LVITEMW lv = {}; lv.iItem = sel; lv.iSubItem = i; lv.pszText = cols[i]; lv.cchTextMax = 4096; lv.mask = LVIF_TEXT;
        ListView_GetItem(hList, &lv);
    }
    std::string fp = ws2s(cols[0]);
    std::string hash = Hasher::sha256(fp);
    std::wstring msg = L"=== File Details ===\n\n";
    msg += L"Path:       " + std::wstring(cols[0]) + L"\n";
    msg += L"Status:     " + std::wstring(cols[1]) + L"\n";
    msg += L"Category:   " + std::wstring(cols[2]) + L"\n";
    msg += L"Threat:     " + std::wstring(cols[3]) + L"\n";
    msg += L"Confidence: " + std::wstring(cols[4]) + L"\n";
    if (!hash.empty()) {
        msg += L"\nSHA256:\n" + s2ws(hash);
        auto sig = g_sigdb.match(hash);
        if (sig) msg += L"\n\nSignature match: " + s2ws(sig->name);
    } else {
        msg += L"\nSHA256: (unavailable - file may not exist or is inaccessible)";
    }
    MessageBoxW(g_hWnd, msg.c_str(), L"Threat Details", MB_OK|MB_ICONINFORMATION);
}

static void showContext(HWND hList, int x, int y) {
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel < 0) return;
    wchar_t path[4096]; LVITEMW lv = {}; lv.iItem = sel; lv.iSubItem = 0; lv.pszText = path; lv.cchTextMax = 4096; lv.mask = LVIF_TEXT;
    ListView_GetItem(hList, &lv);
    std::wstring fp = path;
    std::wstring dir = fp.substr(0, fp.rfind(L'\\'));
    wchar_t st[64]; lv.iSubItem = 1; lv.pszText = st; lv.cchTextMax = 64; ListView_GetItem(g_hList, &lv);
    bool canQ = wcsstr(st, L"CLEAN") == nullptr && wcsstr(st, L"ERROR") == nullptr;

    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, 1001, L"Open File Location");
    AppendMenuW(m, MF_STRING, 1002, L"Copy Path");
    AppendMenuW(m, MF_STRING, 1010, L"Copy Row");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, 1003, L"Details...");
    AppendMenuW(m, MF_STRING, 1004, L"Quarantine File");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, 1005, L"Add to Exclusions");
    AppendMenuW(m, MF_STRING, 1006, L"Shred File");
    EnableMenuItem(m, 1004, canQ ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(m, 1005, !isExcluded(fp) ? MF_ENABLED : MF_GRAYED);

    int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, x, y, 0, hList, nullptr);
    DestroyMenu(m);
    switch (cmd) {
        case 1001: ShellExecuteW(g_hWnd, L"open", dir.c_str(), nullptr, nullptr, SW_SHOW); break;
        case 1002:
            if (OpenClipboard(g_hWnd)) {
                EmptyClipboard();
                auto h = GlobalAlloc(GMEM_MOVEABLE, (fp.size()+1)*2);
                if (h) { memcpy(GlobalLock(h), fp.data(), (fp.size()+1)*2); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT, h); }
                CloseClipboard();
            }
            break;
        case 1010: {
            wchar_t cols[5][4096];
            for (int i = 0; i < 5; i++) {
                lv.iSubItem = i; lv.pszText = cols[i]; lv.cchTextMax = 4096; ListView_GetItem(hList, &lv);
            }
            std::wstring row = std::wstring(cols[0]) + L"\t" + cols[1] + L"\t" + cols[2] + L"\t" + cols[3] + L"\t" + cols[4];
            if (OpenClipboard(g_hWnd)) {
                EmptyClipboard();
                auto h = GlobalAlloc(GMEM_MOVEABLE, (row.size()+1)*2);
                if (h) { memcpy(GlobalLock(h), row.data(), (row.size()+1)*2); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT, h); }
                CloseClipboard();
            }
            break;
        }
        case 1003: showThreatDetails(hList, sel); break;
        case 1004: {
            std::wstring quarDir = s2ws(g_exeDir) + L"\\quarantine";
            CreateDirectoryW(quarDir.c_str(), nullptr);
            auto fn = fp.substr(fp.rfind(L'\\')+1);
            std::wstring dest = quarDir + L"\\" + fn + L".quar";
            if (MoveFileW(fp.c_str(), dest.c_str())) {
                logline(L"[QUARANTINE] Moved: " + fp + L" -> " + dest);
                ListView_DeleteItem(g_hList, sel);
                LVITEMW qv = {}; qv.mask = LVIF_TEXT; qv.iItem = 0;
                qv.pszText = const_cast<wchar_t*>(dest.c_str());
                ListView_InsertItem(g_hQuarList, &qv);
                ListView_SetItemText(g_hQuarList, 0, 1, const_cast<wchar_t*>(fn.c_str()));
                ListView_SetItemText(g_hQuarList, 0, 2, const_cast<wchar_t*>(tds().c_str()));
                MessageBeep(MB_ICONEXCLAMATION);
            } else {
                MessageBoxW(g_hWnd, L"Failed to quarantine file", L"Error", MB_OK|MB_ICONERROR);
            }
            break;
        }
        case 1005:
            if (!isExcluded(fp)) {
                g_exclusions.push_back(fp);
                saveExclusions(); refreshExclList();
                logline(L"[EXCLUSION] Added: " + fp);
            }
            break;
        case 1006: {
            std::wstring q = L"Securely shred and delete:\n" + fp + L"\n\nThis is irreversible!";
            if (MessageBoxW(g_hWnd, q.c_str(), L"Shred File", MB_YESNO|MB_ICONWARNING) == IDYES) {
                if (Shredder::shredAndDelete(fp, 7)) {
                    logline(L"[SHRED] " + fp); ListView_DeleteItem(g_hList, sel);
                } else {
                    MessageBoxW(g_hWnd, L"Failed to shred file", L"Error", MB_OK|MB_ICONERROR);
                }
            }
            break;
        }
    }
}

static void doSort(int col) {
    if (col == g_sortCol) g_sortAsc = !g_sortAsc;
    else { g_sortCol = col; g_sortAsc = true; }
    int n = (int)g_sortItems.size();
    if (!n) return;
    for (int i = 0; i < n; i++) {
        LVITEMW lv = {}; lv.mask = LVIF_PARAM; lv.iItem = i; lv.lParam = i;
        ListView_SetItem(g_hList, &lv);
    }
    ListView_SortItemsEx(g_hList, SortCB, 0);
    InvalidateRect(g_hList, nullptr, TRUE);
}

static void refreshQuarantine() {
    if (!g_hQuarList) return;
    ListView_DeleteAllItems(g_hQuarList);
    std::wstring qd = s2ws(g_exeDir) + L"\\quarantine";
    std::wstring search = qd + L"\\*.quar";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring full = qd + L"\\" + fd.cFileName;
        LVITEMW lv = {}; lv.mask = LVIF_TEXT; lv.iItem = 0;
        lv.pszText = const_cast<wchar_t*>(full.c_str());
        ListView_InsertItem(g_hQuarList, &lv);
        std::wstring orig(fd.cFileName);
        auto dot = orig.rfind(L".quar");
        if (dot != std::wstring::npos) orig = orig.substr(0, dot);
        ListView_SetItemText(g_hQuarList, 0, 1, const_cast<wchar_t*>(orig.c_str()));
        FILETIME ft = fd.ftCreationTime;
        SYSTEMTIME st; FileTimeToSystemTime(&ft, &st);
        wchar_t db[32]; swprintf(db,32,L"%04d-%02d-%02d %02d:%02d",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute);
        ListView_SetItemText(g_hQuarList, 0, 2, db);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void trayNotify(const std::wstring& title, const std::wstring& msg, DWORD infoFlag) {
    NOTIFYICONDATAW nd = {};
    nd.cbSize = sizeof(nd);
    nd.hWnd = g_hWnd;
    nd.uID = 1;
    nd.uFlags = NIF_INFO;
    nd.dwInfoFlags = infoFlag;
    wcsncpy(nd.szInfoTitle, title.c_str(), 63);
    wcsncpy(nd.szInfo, msg.c_str(), 255);
    Shell_NotifyIconW(NIM_MODIFY, &nd);
}

static void refreshDashboard() {
    if (!g_hDashStatus) return;
    SetWindowTextW(g_hDashStatus, (std::wstring(L"Protection: ") + (g_scanning ? L"Scanning..." : L"Active")).c_str());
    SetWindowTextW(g_hDashLastScan, (L"Last Scan: " + g_lastScanTime).c_str());
    SetWindowTextW(g_hDashSigs, (L"Signatures: " + std::to_wstring(g_sigdb.count())).c_str());
    SetWindowTextW(g_hDashThreats, (L"Threats Found: " + std::to_wstring(g_countInfected + g_countHeuristic)).c_str());
    if (g_hRtpLbl)
        SetWindowTextW(g_hRtpLbl, (std::wstring(L"RTP: ") + (g_rtpEnabled ? L"Active" : L"Off")).c_str());
}

// === Process manager ===
static void refreshProcesses() {
    if (!g_hProcList) return;
    g_procEntries.clear();
    ListView_DeleteAllItems(g_hProcList);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) do {
        int idx = (int)g_procEntries.size();
        wchar_t path[MAX_PATH];
        std::string full;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) full = ws2s(path);
            CloseHandle(hProc);
        }
        g_procEntries.emplace_back(ws2s(pe.szExeFile), pe.th32ProcessID);

        LVITEMW lv = {}; lv.mask = LVIF_TEXT; lv.iItem = idx;
        lv.pszText = pe.szExeFile; ListView_InsertItem(g_hProcList, &lv);
        wchar_t pidStr[16]; swprintf(pidStr,16,L"%lu", pe.th32ProcessID);
        ListView_SetItemText(g_hProcList, idx, 1, pidStr);
        wchar_t pathBuf[MAX_PATH]; wcsncpy(pathBuf, s2ws(full).c_str(), MAX_PATH-1);
        ListView_SetItemText(g_hProcList, idx, 2, pathBuf);
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
}

// === Startup manager ===
static void refreshStartup() {
    if (!g_hStartupList) return;
    g_startupEntries.clear();
    ListView_DeleteAllItems(g_hStartupList);

    struct KeyRef { HKEY root; LPCWSTR sub; };
    static const KeyRef keys[] = {
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"},
    };

    for (auto& kr : keys) {
        HKEY hk;
        if (RegOpenKeyExW(kr.root, kr.sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
        DWORD idx = 0;
        wchar_t name[4096], data[4096];
        DWORD nameSz, dataSz, type;
        while (true) {
            nameSz = 4096; dataSz = 4096; type = 0;
            LONG ret = RegEnumValueW(hk, idx++, name, &nameSz, nullptr, &type, (LPBYTE)data, &dataSz);
            if (ret != ERROR_SUCCESS) break;
            std::wstring loc = std::wstring(kr.sub) + L" [" + (kr.root == HKEY_CURRENT_USER ? L"HKCU" : L"HKLM") + L"]";
            g_startupEntries.push_back(loc + L"|" + std::wstring(name) + L"|" + std::wstring(data));

            int i = (int)g_startupEntries.size() - 1;
            LVITEMW lv = {}; lv.mask = LVIF_TEXT; lv.iItem = i;
            lv.pszText = const_cast<wchar_t*>(loc.c_str()); ListView_InsertItem(g_hStartupList, &lv);
            ListView_SetItemText(g_hStartupList, i, 1, name);
            ListView_SetItemText(g_hStartupList, i, 2, data);
        }
        RegCloseKey(hk);
    }
}

// === Create a styled button ===
static HWND MakeBtn(HWND parent, const wchar_t* text, int x, int y, int w, int h, int id) {
    HWND b = CreateWindowW(L"BUTTON", text, WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,
        x,y,w,h, parent, (HMENU)id, g_hInst, nullptr);
    SendMessageW(b, WM_SETFONT, (WPARAM)g_hFont, 0); return b;
}

static HWND MakeLbl(HWND parent, const wchar_t* text, int x, int y, int w, int h) {
    HWND b = CreateWindowW(L"STATIC", text, WS_CHILD|WS_VISIBLE, x,y,w,h, parent, nullptr, g_hInst, nullptr);
    SendMessageW(b, WM_SETFONT, (WPARAM)g_hFont, 0); return b;
}

static HWND MakeCard(HWND parent, int x, int y, int w, int h) {
    return CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE|WS_BORDER, x,y,w,h, parent, nullptr, g_hInst, nullptr);
}

// === WndProc ===
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wP, LPARAM lP) {
    switch (msg) {
    case WM_CREATE: {
        g_hFont = CreateFontW(14,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Consolas");
        g_hFontBold = CreateFontW(15,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_hFontLarge = CreateFontW(28,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_hBrBg = CreateSolidBrush(CLR_BG);
        g_hBrPanel = CreateSolidBrush(CLR_PANEL);
        g_hBrCard = CreateSolidBrush(CLR_CARD);

        RECT rc; GetClientRect(hWnd, &rc);
        g_hTab = CreateWindowW(WC_TABCONTROLW, L"", WS_CHILD|WS_VISIBLE,
            0,0,rc.right-rc.left,rc.bottom-rc.top, hWnd, (HMENU)ID_TAB, g_hInst, nullptr);
        SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hFontBold, 0);

        TCITEMW ti = {}; ti.mask = TCIF_TEXT;
        wchar_t t0[]=L"  Dashboard  ", t1[]=L"  Scan  ", t2[]=L"  Quarantine  ", t3[]=L"  Tools  ", t4[]=L"  Settings  ";
        ti.pszText = t0; TabCtrl_InsertItem(g_hTab, 0, &ti);
        ti.pszText = t1; TabCtrl_InsertItem(g_hTab, 1, &ti);
        ti.pszText = t2; TabCtrl_InsertItem(g_hTab, 2, &ti);
        ti.pszText = t3; TabCtrl_InsertItem(g_hTab, 3, &ti);
        ti.pszText = t4; TabCtrl_InsertItem(g_hTab, 4, &ti);

        // ======= DASHBOARD PANEL =======
        g_hDashPanel = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE, 0,0,1,1, g_hTab, nullptr, g_hInst, nullptr);
        MakeLbl(g_hDashPanel, L"TDEvuris Antivirus", 16, 16, 300, 32);
        // Status cards
        int cw = 130, ch = 80, gap = 12, cx = 16;
        HWND c1 = MakeCard(g_hDashPanel, cx, 56, cw, ch); g_hDashStatus = MakeLbl(c1, L"Protection: Active", 8, 8, cw-16, 60);
        cx += cw + gap;
        HWND c2 = MakeCard(g_hDashPanel, cx, 56, cw, ch); g_hDashLastScan = MakeLbl(c2, L"Last Scan: Never", 8, 8, cw-16, 60);
        cx += cw + gap;
        HWND c3 = MakeCard(g_hDashPanel, cx, 56, cw, ch); g_hDashSigs = MakeLbl(c3, L"Signatures: 0", 8, 8, cw-16, 60);
        cx += cw + gap;
        HWND c4 = MakeCard(g_hDashPanel, cx, 56, cw, ch); g_hDashThreats = MakeLbl(c4, L"Threats Found: 0", 8, 8, cw-16, 60);
        // Quick actions
        MakeLbl(g_hDashPanel, L"Quick Actions", 16, 156, 200, 20);
        MakeBtn(g_hDashPanel, L"Quick Scan", 16, 180, 120, 28, ID_QUICKSCAN_BTN);
        MakeBtn(g_hDashPanel, L"Full Scan", 144, 180, 120, 28, ID_FULLSCAN_BTN);
        MakeBtn(g_hDashPanel, L"Scan Processes", 272, 180, 120, 28, ID_SCANPROC_BTN);
        MakeBtn(g_hDashPanel, L"Scan Network", 16, 214, 120, 28, ID_SCANNET_BTN);
        MakeBtn(g_hDashPanel, L"Scan Registry", 144, 214, 120, 28, ID_SCANREG_BTN);
        MakeBtn(g_hDashPanel, L"Scan Boot", 272, 214, 100, 28, ID_SCANBOOT_BTN);
        MakeBtn(g_hDashPanel, L"Scan Memory", 16, 248, 120, 28, ID_SCANMEM_BTN);
        MakeBtn(g_hDashPanel, L"Open Quarantine", 144, 248, 120, 28, ID_QUAR_SELECTALL_BTN);
        MakeBtn(g_hDashPanel, L"File Shredder", 272, 248, 100, 28, ID_SHRED_BTN);
        MakeBtn(g_hDashPanel, L"Export HTML Report", 16, 282, 150, 28, ID_HTMLREPORT_BTN);
        MakeBtn(g_hDashPanel, L"Update Signatures", 176, 282, 120, 28, ID_UPDATE_BTN);
        MakeBtn(g_hDashPanel, L"All Connections", 306, 282, 120, 28, ID_CONN_LIST_BTN);
        MakeBtn(g_hDashPanel, L"About", 430, 282, 70, 28, ID_ABOUT_BTN);
        // New row: schedule
        MakeLbl(g_hDashPanel, L"Schedule:", 16, 320, 70, 20);
        HWND hSched = CreateWindowW(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST|WS_CHILD|WS_VISIBLE|WS_TABSTOP,
            80, 318, 100, 200, g_hDashPanel, (HMENU)ID_SCHEDULE_COMBO, g_hInst, nullptr);
        SendMessageW(hSched, WM_SETFONT, (WPARAM)g_hFont, 0);
        SendMessageW(hSched, CB_ADDSTRING, 0, (LPARAM)L"Off");
        SendMessageW(hSched, CB_ADDSTRING, 0, (LPARAM)L"Every 30m");
        SendMessageW(hSched, CB_ADDSTRING, 0, (LPARAM)L"Every 1h");
        SendMessageW(hSched, CB_ADDSTRING, 0, (LPARAM)L"Every 2h");
        SendMessageW(hSched, CB_ADDSTRING, 0, (LPARAM)L"Daily");
        SendMessageW(hSched, CB_SETCURSEL, 0, 0);
        // RTP indicator
        g_hRtpLbl = MakeLbl(g_hDashPanel, L"", 190, 318, 300, 20);

        // ======= SCAN PANEL =======
        g_hScanPanel = CreateWindowW(L"STATIC", L"", WS_CHILD, 0,0,1,1, g_hTab, nullptr, g_hInst, nullptr);
        g_hAdminLbl = CreateWindowW(L"STATIC", L"\x26A0 Not running as admin",
            WS_CHILD|WS_VISIBLE, 12, 6, 300, 18, g_hScanPanel, (HMENU)ID_ADMIN_LBL, g_hInst, nullptr);
        if (Scanner::isAdmin()) ShowWindow(g_hAdminLbl, SW_HIDE);

        MakeLbl(g_hScanPanel, L"Target:", 12, 30, 45, 20);
        g_hDriveCombo = CreateWindowW(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST|WS_CHILD|WS_VISIBLE|WS_TABSTOP,
            60,28,140,200, g_hScanPanel, (HMENU)ID_DRIVE_COMBO, g_hInst, nullptr);
        SendMessageW(g_hDriveCombo, WM_SETFONT, (WPARAM)g_hFont, 0);
        wchar_t drives[260]; GetLogicalDriveStringsW(260, drives);
        for (wchar_t* p = drives; *p; p += wcslen(p)+1) {
            UINT t = GetDriveTypeW(p);
            const wchar_t* l = L"";
            if (t==DRIVE_FIXED) l=L"  [Local]"; else if (t==DRIVE_REMOVABLE) l=L"  [USB]";
            else if (t==DRIVE_CDROM) l=L"  [CD]"; else if (t==DRIVE_REMOTE) l=L"  [Net]";
            SendMessageW(g_hDriveCombo, CB_ADDSTRING, 0, (LPARAM)(std::wstring(p)+l).c_str());
        }
        SendMessageW(g_hDriveCombo, CB_SETCURSEL, 0, 0);

        int bx = 210;
        g_hScanBtn = MakeBtn(g_hScanPanel, L"Scan Disk", bx, 28, 70, 24, ID_SCAN_BTN);
        SendMessageW(g_hScanBtn, WM_SETFONT, (WPARAM)g_hFontBold, 0);
        bx += 74;
        g_hStopBtn = MakeBtn(g_hScanPanel, L"Stop", bx, 28, 45, 24, ID_STOP_BTN); EnableWindow(g_hStopBtn, FALSE);
        bx += 49;
        g_hClearBtn = MakeBtn(g_hScanPanel, L"Clear", bx, 28, 45, 24, ID_CLEAR_BTN);
        bx += 49;
        g_hLogBtn = MakeBtn(g_hScanPanel, L"Log", bx, 28, 35, 24, ID_LOG_BTN);
        bx += 39;
        MakeLbl(g_hScanPanel, L"Mode:", bx, 30, 38, 20);
        HWND hProf = CreateWindowW(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST|WS_CHILD|WS_VISIBLE|WS_TABSTOP,
            bx+36,28,70,200, g_hScanPanel, (HMENU)ID_PROFILE_COMBO, g_hInst, nullptr);
        SendMessageW(hProf, WM_SETFONT, (WPARAM)g_hFont, 0);
        SendMessageW(hProf, CB_ADDSTRING, 0, (LPARAM)L"Full");
        SendMessageW(hProf, CB_ADDSTRING, 0, (LPARAM)L"Quick");
        SendMessageW(hProf, CB_SETCURSEL, 0, 0);
        // Profile depth toggle
        bx += 112;

        int y2 = 56;
        MakeBtn(g_hScanPanel, L"Scan Processes", 12, y2, 100, 22, ID_SCANPROC_BTN);
        MakeBtn(g_hScanPanel, L"Scan Network", 116, y2, 95, 22, ID_SCANNET_BTN);
        MakeBtn(g_hScanPanel, L"Scan Registry", 215, y2, 95, 22, ID_SCANREG_BTN);
        MakeBtn(g_hScanPanel, L"Export CSV", 314, y2, 80, 22, ID_EXPORT_BTN);

        g_hProgress = CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD|WS_VISIBLE|PBS_SMOOTH,
            12, 82, 390, 14, g_hScanPanel, (HMENU)ID_PROGRESS, g_hInst, nullptr);
        SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0,100));
        SendMessageW(g_hProgress, PBM_SETBARCOLOR, 0, RGB(0,160,0));
        SendMessageW(g_hProgress, PBM_SETBKCOLOR, 0, RGB(45,45,50));

        for (int i = 0; i < 6; i++) {
            g_hStats[i] = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE,
                10, 102+i*17, 400, 15, g_hScanPanel, (HMENU)(ID_STATS_TOTAL+i), g_hInst, nullptr);
            SendMessageW(g_hStats[i], WM_SETFONT, (WPARAM)g_hFont, 0);
        }
        updateStats();

        g_hList = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|WS_TABSTOP,
            10, 205, 452, 190, g_hScanPanel, (HMENU)ID_RESULT_LIST, g_hInst, nullptr);
        LVCOLUMNW lc = {}; lc.mask = LVCF_TEXT|LVCF_WIDTH;
        lc.pszText = (LPWSTR)L"File"; lc.cx = 170; ListView_InsertColumn(g_hList,0,&lc);
        lc.pszText = (LPWSTR)L"Status"; lc.cx = 80; ListView_InsertColumn(g_hList,1,&lc);
        lc.pszText = (LPWSTR)L"Category"; lc.cx = 70; ListView_InsertColumn(g_hList,2,&lc);
        lc.pszText = (LPWSTR)L"Threat"; lc.cx = 110; ListView_InsertColumn(g_hList,3,&lc);
        lc.pszText = (LPWSTR)L"Conf"; lc.cx = 40; ListView_InsertColumn(g_hList,4,&lc);
        ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_INFOTIP);
        ListView_SetBkColor(g_hList, CLR_BG); ListView_SetTextBkColor(g_hList, CLR_BG);
        ListView_SetTextColor(g_hList, CLR_TEXT);
        SendMessageW(g_hList, WM_SETFONT, (WPARAM)g_hFont, 0);

        // ======= TOOLS PANEL =======
        g_hToolsPanel = CreateWindowW(L"STATIC", L"", WS_CHILD, 0,0,1,1, g_hTab, nullptr, g_hInst, nullptr);

        // Process manager
        MakeLbl(g_hToolsPanel, L"Process Manager", 12, 12, 200, 20);
        g_hProcList = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|WS_TABSTOP,
            12, 34, 350, 180, g_hToolsPanel, (HMENU)ID_TOOLS_PROC_LIST, g_hInst, nullptr);
        LVCOLUMNW pc = {}; pc.mask = LVCF_TEXT|LVCF_WIDTH;
        pc.pszText = (LPWSTR)L"Process"; pc.cx = 140; ListView_InsertColumn(g_hProcList,0,&pc);
        pc.pszText = (LPWSTR)L"PID"; pc.cx = 60; ListView_InsertColumn(g_hProcList,1,&pc);
        pc.pszText = (LPWSTR)L"Path"; pc.cx = 140; ListView_InsertColumn(g_hProcList,2,&pc);
        ListView_SetExtendedListViewStyle(g_hProcList, LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
        ListView_SetBkColor(g_hProcList, CLR_BG); ListView_SetTextBkColor(g_hProcList, CLR_BG);
        ListView_SetTextColor(g_hProcList, CLR_TEXT);
        SendMessageW(g_hProcList, WM_SETFONT, (WPARAM)g_hFont, 0);
        MakeBtn(g_hToolsPanel, L"Refresh", 370, 34, 70, 24, ID_TOOLS_PROC_REFRESH);
        MakeBtn(g_hToolsPanel, L"Kill", 370, 62, 70, 24, ID_TOOLS_PROC_KILL);

        // Startup manager
        MakeLbl(g_hToolsPanel, L"Startup Manager", 12, 228, 200, 20);
        g_hStartupList = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|WS_TABSTOP,
            12, 250, 350, 180, g_hToolsPanel, (HMENU)ID_TOOLS_STARTUP_LIST, g_hInst, nullptr);
        LVCOLUMNW sc = {}; sc.mask = LVCF_TEXT|LVCF_WIDTH;
        sc.pszText = (LPWSTR)L"Location"; sc.cx = 160; ListView_InsertColumn(g_hStartupList,0,&sc);
        sc.pszText = (LPWSTR)L"Value"; sc.cx = 100; ListView_InsertColumn(g_hStartupList,1,&sc);
        sc.pszText = (LPWSTR)L"Data"; sc.cx = 90; ListView_InsertColumn(g_hStartupList,2,&sc);
        ListView_SetExtendedListViewStyle(g_hStartupList, LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
        ListView_SetBkColor(g_hStartupList, CLR_BG); ListView_SetTextBkColor(g_hStartupList, CLR_BG);
        ListView_SetTextColor(g_hStartupList, CLR_TEXT);
        SendMessageW(g_hStartupList, WM_SETFONT, (WPARAM)g_hFont, 0);
        MakeBtn(g_hToolsPanel, L"Refresh", 370, 250, 70, 24, ID_TOOLS_STARTUP_REFRESH);
        MakeBtn(g_hToolsPanel, L"Disable", 370, 278, 70, 24, ID_TOOLS_STARTUP_DISABLE);

        // ======= QUARANTINE PANEL =======
        g_hQuarPanel = CreateWindowW(L"STATIC", L"", WS_CHILD, 0,0,1,1, g_hTab, nullptr, g_hInst, nullptr);
        g_hQuarList = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|WS_TABSTOP,
            12,12,450,250, g_hQuarPanel, (HMENU)ID_QUAR_LIST, g_hInst, nullptr);
        LVCOLUMNW qc = {}; qc.mask = LVCF_TEXT|LVCF_WIDTH;
        qc.pszText = (LPWSTR)L"Quarantine Path"; qc.cx = 200; ListView_InsertColumn(g_hQuarList,0,&qc);
        qc.pszText = (LPWSTR)L"Original File"; qc.cx = 150; ListView_InsertColumn(g_hQuarList,1,&qc);
        qc.pszText = (LPWSTR)L"Date Quarantined"; qc.cx = 100; ListView_InsertColumn(g_hQuarList,2,&qc);
        ListView_SetExtendedListViewStyle(g_hQuarList, LVS_EX_FULLROWSELECT);
        ListView_SetBkColor(g_hQuarList, CLR_BG); ListView_SetTextBkColor(g_hQuarList, CLR_BG);
        ListView_SetTextColor(g_hQuarList, CLR_TEXT);
        SendMessageW(g_hQuarList, WM_SETFONT, (WPARAM)g_hFont, 0);

        g_hQuarRestore = MakeBtn(g_hQuarPanel, L"Restore", 12, 268, 70, 24, ID_QUAR_RESTORE_BTN);
        g_hQuarDelete   = MakeBtn(g_hQuarPanel, L"Delete", 86, 268, 70, 24, ID_QUAR_DELETE_BTN);
        g_hQuarSelectAll= MakeBtn(g_hQuarPanel, L"Select All", 160, 268, 80, 24, ID_QUAR_SELECTALL_BTN);
        g_hQuarEmpty    = MakeBtn(g_hQuarPanel, L"Empty All", 244, 268, 80, 24, ID_QUAR_EMPTY_BTN);
        refreshQuarantine();

        // ======= SETTINGS PANEL =======
        g_hSetPanel = CreateWindowW(L"STATIC", L"", WS_CHILD, 0,0,1,1, g_hTab, nullptr, g_hInst, nullptr);
        g_hSetSigCount = MakeLbl(g_hSetPanel, L"", 12, 12, 400, 20);
        g_hSetHeur = CreateWindowW(L"BUTTON", L"Enable Heuristics",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 12, 40, 200, 24, g_hSetPanel, (HMENU)ID_SETT_HEUR_TOGGLE, g_hInst, nullptr);
        SendMessageW(g_hSetHeur, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(g_hSetHeur, WM_SETFONT, (WPARAM)g_hFont, 0);

        // Real-time protection
        HWND hRtp = CreateWindowW(L"BUTTON", L"Real-time Protection",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 12, 66, 240, 24, g_hSetPanel, (HMENU)ID_SETT_RTP_TOGGLE, g_hInst, nullptr);
        SendMessageW(hRtp, WM_SETFONT, (WPARAM)g_hFont, 0);
        MakeLbl(g_hSetPanel, L"Monitors file system changes in real time", 28, 84, 400, 18);

        // Startup with Windows
        g_hSetStartup = CreateWindowW(L"BUTTON", L"Start with Windows",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 12, 108, 240, 24, g_hSetPanel, (HMENU)ID_SETT_STARTUP_TOGGLE, g_hInst, nullptr);
        SendMessageW(g_hSetStartup, WM_SETFONT, (WPARAM)g_hFont, 0);
        HKEY hk; wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        bool hasStartup = false;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            wchar_t val[MAX_PATH]; DWORD sz = sizeof(val);
            hasStartup = (RegQueryValueExW(hk, L"TDEvuris", nullptr, nullptr, (LPBYTE)val, &sz) == ERROR_SUCCESS);
            RegCloseKey(hk);
        }
        if (hasStartup) SendMessageW(g_hSetStartup, BM_SETCHECK, BST_CHECKED, 0);

        // Minimize to tray
        g_hSetTray = CreateWindowW(L"BUTTON", L"Minimize to System Tray",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 12, 134, 240, 24, g_hSetPanel, (HMENU)ID_SETT_TRAY_TOGGLE, g_hInst, nullptr);
        SendMessageW(g_hSetTray, WM_SETFONT, (WPARAM)g_hFont, 0);
        MakeLbl(g_hSetPanel, L"Minimizes instead of closing to background", 28, 152, 400, 18);

        // Exclusion list
        MakeLbl(g_hSetPanel, L"Exclusion List:", 12, 180, 200, 20);
        g_hSetExclList = CreateWindowW(WC_LISTBOX, L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY,
            12, 200, 350, 120, g_hSetPanel, (HMENU)ID_SETT_EXCL_LIST, g_hInst, nullptr);
        SendMessageW(g_hSetExclList, WM_SETFONT, (WPARAM)g_hFont, 0);
        g_hSetExclAdd = MakeBtn(g_hSetPanel, L"Add Path...", 370, 200, 80, 24, ID_SETT_EXCL_ADD);
        g_hSetExclRemove = MakeBtn(g_hSetPanel, L"Remove", 370, 228, 80, 24, ID_SETT_EXCL_REMOVE);
        loadExclusions(); refreshExclList();

        // Status bar
        g_hStatus = CreateWindowW(STATUSCLASSNAMEW, L"Ready", WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,
            0,0,0,0, hWnd, nullptr, g_hInst, nullptr);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, 0);

        // Load sigs
        std::string db;
        for (auto c : {std::filesystem::path(g_exeDir)/"signatures.json",
                       std::filesystem::path(g_exeDir).parent_path()/"signatures.json",
                       std::filesystem::path("./signatures.json")})
            if (std::filesystem::exists(c)) { db = c.string(); break; }
        if (!g_sigdb.load(db)) SetWindowTextW(hWnd, L"TDEvuris - NO SIGS");
        else {
            auto t = L"TDEvuris - " + std::to_wstring(g_sigdb.count()) + L" sigs" +
                     (Scanner::isAdmin() ? L" [ADMIN]" : L" [USER]");
            SetWindowTextW(hWnd, t.c_str());
        }
        SetWindowTextW(g_hSetSigCount, (L"Loaded signatures: " + std::to_wstring(g_sigdb.count())).c_str());

        // Show dashboard
        ShowWindow(g_hScanPanel, SW_HIDE);
        ShowWindow(g_hQuarPanel, SW_HIDE);
        ShowWindow(g_hToolsPanel, SW_HIDE);
        ShowWindow(g_hSetPanel, SW_HIDE);
        refreshDashboard();
        break;
    }

    case WM_NOTIFY: {
        auto* h = (NMHDR*)lP;
        if (h->code == TCN_SELCHANGE && h->hwndFrom == g_hTab) {
            int s = TabCtrl_GetCurSel(g_hTab);
            ShowWindow(g_hDashPanel, s==0 ? SW_SHOW : SW_HIDE);
            ShowWindow(g_hScanPanel, s==1 ? SW_SHOW : SW_HIDE);
            ShowWindow(g_hQuarPanel, s==2 ? SW_SHOW : SW_HIDE);
            ShowWindow(g_hToolsPanel, s==3 ? SW_SHOW : SW_HIDE);
            ShowWindow(g_hSetPanel,  s==4 ? SW_SHOW : SW_HIDE);
            if (s == 3) { refreshProcesses(); refreshStartup(); }
            return 0;
        }
        if (h->hwndFrom == g_hList && h->code == NM_CUSTOMDRAW) return CDraw(lP);
        if (h->hwndFrom == g_hList && h->code == LVN_COLUMNCLICK) {
            auto* col = (NMLISTVIEW*)lP; doSort(col->iSubItem); return 0;
        }
        if (h->hwndFrom == g_hList && h->code == NM_RCLICK) {
            POINT p; GetCursorPos(&p); showContext(g_hList, p.x, p.y); return 0;
        }
        if (h->hwndFrom == g_hList && h->code == LVN_GETINFOTIP) {
            auto* tip = (NMLVGETINFOTIPW*)lP;
            wchar_t buf[4096];
            LVITEMW lv = {}; lv.iItem = tip->iItem; lv.iSubItem = 0; lv.pszText = buf; lv.cchTextMax = 4096; lv.mask = LVIF_TEXT;
            ListView_GetItem(g_hList, &lv);
            wcsncpy(tip->pszText, buf, tip->cchTextMax - 1);
            return 0;
        }
        if (h->hwndFrom == g_hQuarList && h->code == NM_RCLICK) {
            int sel = ListView_GetNextItem(g_hQuarList, -1, LVNI_SELECTED);
            if (sel < 0) return 0;
            wchar_t buf[4096]; LVITEMW lv = {}; lv.iItem = sel; lv.iSubItem = 0; lv.pszText = buf; lv.cchTextMax = 4096; lv.mask = LVIF_TEXT;
            ListView_GetItem(g_hQuarList, &lv);
            POINT p; GetCursorPos(&p);
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, 2001, L"Restore");
            AppendMenuW(m, MF_STRING, 2002, L"Delete Permanently");
            int cmd = TrackPopupMenu(m, TPM_RETURNCMD|TPM_NONOTIFY|TPM_RIGHTBUTTON, p.x,p.y,0,g_hQuarList,nullptr);
            DestroyMenu(m);
            if (cmd == 2001) {
                std::wstring orig = std::wstring(buf).substr(0, std::wstring(buf).rfind(L".quar"));
                if (MoveFileW(buf, orig.c_str())) { logline(L"[RESTORE] " + std::wstring(buf)); ListView_DeleteItem(g_hQuarList, sel); }
            } else if (cmd == 2002) {
                if (DeleteFileW(buf)) { logline(L"[DELETE] " + std::wstring(buf)); ListView_DeleteItem(g_hQuarList, sel); }
            }
            return 0;
        }
        break;
    }

    case WM_COMMAND: {
        switch (LOWORD(wP)) {
        case ID_QUICKSCAN_BTN:
        case ID_SCAN_BTN: {
            int sel = (int)SendMessageW(g_hDriveCombo, CB_GETCURSEL,0,0);
            if (sel == CB_ERR) break;
            wchar_t b[260]; SendMessageW(g_hDriveCombo, CB_GETLBTEXT, sel, (LPARAM)b);
            std::wstring d(b); auto sp = d.find(L"  "); if (sp != std::wstring::npos) d = d.substr(0, sp);

            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_scannedFiles=g_totalFiles=g_skippedFiles=0;
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            updateStats();
            openLog();
            logline(L"===== Scan: " + d + L" =====");
            logline(L"Admin: " + std::wstring(Scanner::isAdmin() ? L"Yes" : L"No"));
            logline(L"Sigs: " + std::to_wstring(g_sigdb.count()));
            SetWindowTextW(g_hStatus, (L"Log: " + g_logPath).c_str());
            enableScanCtrls(true);
            g_scanning = true;
            g_scanThread = std::thread(scanThread, d);
            g_scanThread.detach();
            break;
        }
        case ID_FULLSCAN_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_scannedFiles=g_totalFiles=g_skippedFiles=0;
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            updateStats(); openLog();
            logline(L"===== Full Scan: ALL DRIVES =====");
            SetWindowTextW(g_hStatus, L"Full scan starting...");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                wchar_t drives[260]; GetLogicalDriveStringsW(260, drives);
                for (wchar_t* p = drives; *p; p += wcslen(p)+1) {
                    if (GetDriveTypeW(p) != DRIVE_FIXED) continue;
                    auto prog = [&](const std::string& f, int s, int t, int sk, const std::string&) {
                        g_scannedFiles = s; g_totalFiles = t; g_skippedFiles = sk;
                        PostMessageW(g_hWnd, WM_SCAN_PROGRESS, (WPARAM)s, (LPARAM)t);
                    };
                    auto res = [&](const ScanResult& r) {
                        if (isExcluded(s2ws(r.filepath))) return;
                        PostMessageW(g_hWnd, WM_SCAN_RESULT, 0, (LPARAM)new ScanResult(r));
                    };
                    g_scanner = new Scanner(g_sigdb);
                    auto sum = g_scanner->scanDirectory(ws2s(p), prog, res);
                    delete g_scanner; g_scanner = nullptr;
                }
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary{});
            });
            g_scanThread.detach();
            break;
        }
        case ID_SCANPROC_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            openLog(); logline(L"===== Process Scan =====");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                auto prog = [&](const std::string&, int s, int t, int sk, const std::string&) {
                    PostMessageW(g_hWnd, WM_SCAN_PROGRESS, (WPARAM)s, (LPARAM)t); };
                auto res = [&](const ScanResult& r) {
                    PostMessageW(g_hWnd, WM_SCAN_RESULT, 0, (LPARAM)new ScanResult(r)); };
                g_scanner = new Scanner(g_sigdb);
                auto sum = g_scanner->scanProcesses(prog, res);
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary(sum));
            });
            g_scanThread.detach();
            break;
        }
        case ID_SCANNET_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            openLog(); logline(L"===== Network Scan =====");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                NetworkScanner ns;
                auto results = ns.analyze();
                g_countTotal = (int)results.size();
                for (auto& nr : results) {
                    int idx = g_itemCounter++;
                    SortItem si = {}; si.idx = idx; si.status = HeuristicMatch;
                    si.cols[0] = s2ws(nr.conn.procName.empty() ? ("PID:"+std::to_string(nr.conn.pid)) : nr.conn.procName);
                    si.cols[1] = L"NET";
                    si.cols[2] = s2ws(nr.category);
                    si.cols[3] = s2ws(nr.threatName);
                    wchar_t c[16]; swprintf(c,16,L"%.0f%%",nr.confidence*100); si.cols[4]=c;
                    LVITEMW lv={}; lv.mask=LVIF_TEXT|LVIF_PARAM; lv.iItem=idx;
                    lv.pszText=const_cast<wchar_t*>(si.cols[0].c_str());
                    ListView_InsertItem(g_hList,&lv);
                    for (int s=1;s<5;s++) ListView_SetItemText(g_hList,idx,s,const_cast<wchar_t*>(si.cols[s].c_str()));
                    g_sortItems.push_back(si); g_countHeuristic++;
                    logline(L"[NET][" + si.cols[2] + L"] " + si.cols[3] + L"  " + si.cols[0]);
                }
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary{0,Scanner::isAdmin()});
            });
            g_scanThread.detach();
            break;
        }
        case ID_SCANREG_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            openLog(); logline(L"===== Registry Scan =====");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                RegistryScanner rs;
                auto results = rs.analyze();
                g_countTotal = (int)results.size();
                for (auto& rr : results) {
                    int idx = g_itemCounter++;
                    SortItem si = {}; si.idx = idx; si.status = HeuristicMatch;
                    si.cols[0] = s2ws(rr.entry.key);
                    si.cols[1] = L"REG";
                    si.cols[2] = s2ws(rr.threatCategory);
                    si.cols[3] = s2ws(rr.threatName);
                    wchar_t c[16]; swprintf(c,16,L"%.0f%%",rr.confidence*100); si.cols[4]=c;
                    LVITEMW lv={}; lv.mask=LVIF_TEXT|LVIF_PARAM; lv.iItem=idx;
                    lv.pszText=const_cast<wchar_t*>(si.cols[0].c_str());
                    ListView_InsertItem(g_hList,&lv);
                    for (int s=1;s<5;s++) ListView_SetItemText(g_hList,idx,s,const_cast<wchar_t*>(si.cols[s].c_str()));
                    g_sortItems.push_back(si); g_countHeuristic++;
                    logline(L"[REG][" + si.cols[2] + L"] " + si.cols[3] + L"  " + si.cols[0]);
                }
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary{0,Scanner::isAdmin()});
            });
            g_scanThread.detach();
            break;
        }
        case ID_EXPORT_BTN: {
            wchar_t p[260]={}; OPENFILENAMEW ofn = {}; ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hWnd; ofn.lpstrFilter=L"CSV\0*.csv\0All\0*.*\0";
            ofn.lpstrFile=p; ofn.nMaxFile=260; ofn.lpstrDefExt=L"csv";
            ofn.Flags=OFN_OVERWRITEPROMPT|OFN_NOCHANGEDIR;
            if (GetSaveFileNameW(&ofn)) {
                HANDLE h = CreateFileW(p, GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,0,nullptr);
                if (h != INVALID_HANDLE_VALUE) {
                    const char* hdr = "File,Status,Category,Threat,Confidence\r\n";
                    DWORD written; WriteFile(h, hdr, strlen(hdr), &written, nullptr);
                    for (auto& item : g_sortItems) {
                        std::string line = ws2s(item.cols[0]) + "," + ws2s(item.cols[1]) + ","
                            + ws2s(item.cols[2]) + "," + ws2s(item.cols[3]) + "," + ws2s(item.cols[4]) + "\r\n";
                        WriteFile(h, line.data(), (DWORD)line.size(), &written, nullptr);
                    }
                    CloseHandle(h); logline(L"[EXPORT] " + std::wstring(p));
                }
            }
            break;
        }
        case ID_STOP_BTN:
            if (g_scanner) g_scanner->stop();
            g_scanning = false; enableScanCtrls(false);
            SetWindowTextW(g_hStatus, L"Stopped"); logline(L"=== STOPPED ===");
            break;
        case ID_CLEAR_BTN:
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            break;
        case ID_LOG_BTN:
            if (!g_logPath.empty()) ShellExecuteW(hWnd, L"open", g_logPath.c_str(), nullptr, nullptr, SW_SHOW);
            else SetWindowTextW(g_hStatus, L"No log");
            break;

        // === Quarantine commands ===
        case ID_QUAR_RESTORE_BTN: case ID_QUAR_DELETE_BTN: {
            int s = ListView_GetNextItem(g_hQuarList, -1, LVNI_SELECTED);
            if (s < 0) break;
            wchar_t p[4096]; LVITEMW lv = {}; lv.iItem = s; lv.iSubItem = 0; lv.pszText = p; lv.cchTextMax = 4096; lv.mask = LVIF_TEXT;
            ListView_GetItem(g_hQuarList, &lv);
            std::wstring src = p;
            std::wstring orig = src.substr(0, src.rfind(L".quar"));
            if (LOWORD(wP) == ID_QUAR_RESTORE_BTN) {
                if (MoveFileW(src.c_str(), orig.c_str())) { logline(L"[RESTORE] " + src); ListView_DeleteItem(g_hQuarList, s); }
            } else {
                if (DeleteFileW(src.c_str())) { logline(L"[DELETE] " + src); ListView_DeleteItem(g_hQuarList, s); }
            }
            break;
        }
        case ID_QUAR_SELECTALL_BTN: {
            int n = ListView_GetItemCount(g_hQuarList);
            for (int i = 0; i < n; i++) ListView_SetItemState(g_hQuarList, i, LVIS_SELECTED, LVIS_SELECTED);
            TabCtrl_SetCurSel(g_hTab, 2);
            ShowWindow(g_hDashPanel, SW_HIDE); ShowWindow(g_hScanPanel, SW_HIDE);
            ShowWindow(g_hQuarPanel, SW_SHOW); ShowWindow(g_hSetPanel, SW_HIDE);
            break;
        }
        case ID_QUAR_EMPTY_BTN: {
            if (MessageBoxW(hWnd, L"Permanently delete ALL quarantined files?", L"Empty Quarantine",
                            MB_YESNO|MB_ICONWARNING) == IDYES) {
                std::wstring qd = s2ws(g_exeDir) + L"\\quarantine";
                std::wstring search = qd + L"\\*.quar";
                WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW(search.c_str(), &fd);
                if (h != INVALID_HANDLE_VALUE) {
                    do { DeleteFileW((qd + L"\\" + fd.cFileName).c_str()); } while (FindNextFileW(h, &fd));
                    FindClose(h);
                }
                refreshQuarantine(); logline(L"[QUARANTINE] Emptied");
            }
            break;
        }
        // === Settings commands ===
        case ID_SETT_RTP_TOGGLE: {
            bool en = SendMessageW((HWND)lP, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (en) {
                g_rtpEnabled = true;
                g_watcher.start(L"C:\\", [](const std::wstring& path, DWORD) {
                    PostMessageW(g_hWnd, WM_WATCHER_EVENT, 0, (LPARAM)new std::wstring(path));
                });
                logline(L"[RTP] Real-time protection ENABLED");
            } else {
                g_rtpEnabled = false;
                g_watcher.stop();
                logline(L"[RTP] Real-time protection DISABLED");
            }
            refreshDashboard();
            break;
        }
        case ID_SETT_HEUR_TOGGLE: break;
        case ID_SETT_STARTUP_TOGGLE: {
            bool en = SendMessageW(g_hSetStartup, BM_GETCHECK, 0, 0) == BST_CHECKED;
            HKEY hk;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                if (en) {
                    wchar_t exePath[MAX_PATH]; GetModuleFileNameW(nullptr, exePath, MAX_PATH);
                    RegSetValueExW(hk, L"TDEvuris", 0, REG_SZ, (BYTE*)exePath, (wcslen(exePath)+1)*2);
                } else {
                    RegDeleteValueW(hk, L"TDEvuris");
                }
                RegCloseKey(hk);
            }
            break;
        }
        case ID_SETT_TRAY_TOGGLE:
            g_minimizeToTray = SendMessageW(g_hSetTray, BM_GETCHECK, 0, 0) == BST_CHECKED;
            break;
        case ID_SETT_EXCL_ADD: {
            wchar_t p[260]={}; OPENFILENAMEW ofn = {}; ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hWnd; ofn.lpstrFilter=L"All Files\0*.*\0";
            ofn.lpstrFile=p; ofn.nMaxFile=260; ofn.Flags=OFN_FILEMUSTEXIST|OFN_NOCHANGEDIR;
            if (GetOpenFileNameW(&ofn)) {
                g_exclusions.push_back(p);
                saveExclusions(); refreshExclList();
                logline(L"[EXCLUSION] Added: " + std::wstring(p));
            }
            break;
        }
        case ID_SETT_EXCL_REMOVE: {
            int s = (int)SendMessageW(g_hSetExclList, LB_GETCURSEL, 0, 0);
            if (s >= 0 && s < (int)g_exclusions.size()) {
                logline(L"[EXCLUSION] Removed: " + g_exclusions[s]);
                g_exclusions.erase(g_exclusions.begin() + s);
                saveExclusions(); refreshExclList();
            }
            break;
        }
        case ID_SCANBOOT_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            openLog(); logline(L"===== Boot Sector Scan =====");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                BootScanner bs;
                auto results = bs.scanAll();
                g_countTotal = (int)results.size();
                for (auto& br : results) {
                    int idx = g_itemCounter++;
                    SortItem si = {}; si.idx = idx; si.status = br.suspicious ? HeuristicMatch : Clean;
                    si.cols[0] = s2ws(br.device);
                    si.cols[1] = br.suspicious ? L"BOOT" : L"CLEAN";
                    si.cols[2] = s2ws(br.category);
                    si.cols[3] = s2ws(br.threatName);
                    wchar_t c[16]; swprintf(c,16,L"%.0f%%",br.confidence*100); si.cols[4]=c;
                    LVITEMW lv={}; lv.mask=LVIF_TEXT|LVIF_PARAM; lv.iItem=idx;
                    lv.pszText=const_cast<wchar_t*>(si.cols[0].c_str());
                    ListView_InsertItem(g_hList,&lv);
                    for (int s=1;s<5;s++) ListView_SetItemText(g_hList,idx,s,const_cast<wchar_t*>(si.cols[s].c_str()));
                    g_sortItems.push_back(si);
                    if (br.suspicious) g_countHeuristic++; else g_countClean++;
                    logline(L"[BOOT][" + si.cols[2] + L"] " + si.cols[3] + L"  " + si.cols[0]);
                }
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary{0,Scanner::isAdmin()});
            });
            g_scanThread.detach();
            break;
        }
        case ID_SCANMEM_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            openLog(); logline(L"===== Memory Scan =====");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                MemoryScanner ms;
                auto results = ms.scanAll();
                g_countTotal = (int)results.size();
                for (auto& mr : results) {
                    int idx = g_itemCounter++;
                    SortItem si = {}; si.idx = idx; si.status = mr.suspicious ? HeuristicMatch : Clean;
                    si.cols[0] = s2ws("PID " + std::to_string(mr.pid) + " " + mr.procName);
                    si.cols[1] = mr.suspicious ? L"MEM" : L"CLEAN";
                    si.cols[2] = s2ws(mr.category);
                    si.cols[3] = s2ws(mr.threatName);
                    wchar_t c[16]; swprintf(c,16,L"%.0f%%",mr.confidence*100); si.cols[4]=c;
                    LVITEMW lv={}; lv.mask=LVIF_TEXT|LVIF_PARAM; lv.iItem=idx;
                    lv.pszText=const_cast<wchar_t*>(si.cols[0].c_str());
                    ListView_InsertItem(g_hList,&lv);
                    for (int s=1;s<5;s++) ListView_SetItemText(g_hList,idx,s,const_cast<wchar_t*>(si.cols[s].c_str()));
                    g_sortItems.push_back(si);
                    if (mr.suspicious) g_countHeuristic++; else g_countClean++;
                    logline(L"[MEM][" + si.cols[2] + L"] " + si.cols[3] + L"  " + si.cols[0]);
                }
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary{0,Scanner::isAdmin()});
            });
            g_scanThread.detach();
            break;
        }
        case ID_SHRED_BTN: {
            wchar_t p[260]={}; OPENFILENAMEW ofn = {}; ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hWnd; ofn.lpstrFilter=L"All Files\0*.*\0";
            ofn.lpstrFile=p; ofn.nMaxFile=260; ofn.Flags=OFN_FILEMUSTEXIST|OFN_NOCHANGEDIR;
            if (GetOpenFileNameW(&ofn)) {
                std::wstring msg = L"Permanently shred and delete:\n" + std::wstring(p) + L"\n\nThis cannot be undone!";
                if (MessageBoxW(hWnd, msg.c_str(), L"File Shredder", MB_YESNO|MB_ICONWARNING) == IDYES) {
                    SetWindowTextW(g_hStatus, L"Shredding...");
                    EnableWindow((HWND)lP, FALSE);
                    g_scanThread = std::thread([p]() {
                        bool ok = Shredder::shredAndDelete(p, 7);
                        PostMessageW(g_hWnd, WM_SCAN_DONE, ok ? 1 : 0, (LPARAM)new ScanSummary{0,Scanner::isAdmin()});
                    });
                    g_scanThread.detach();
                }
            }
            break;
        }
        case ID_SCHEDULE_COMBO: {
            if (HIWORD(wP) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW((HWND)lP, CB_GETCURSEL, 0, 0);
                if (g_scheduleTimer) { KillTimer(hWnd, g_scheduleTimer); g_scheduleTimer = 0; }
                if (sel > 0) {
                    static const UINT intervals[] = {0, 1800000, 3600000, 7200000, 86400000};
                    if (sel < 6) g_scheduleTimer = SetTimer(hWnd, 1, intervals[sel], nullptr);
                }
            }
            break;
        }
        case ID_ABOUT_BTN: {
            std::wstring about =
                L"TDEvuris Antivirus v2.1\n\n"
                L"A signature + heuristic based antivirus\n"
                L"written in C++17 with the Win32 API.\n\n"
                L"Features:\n"
                L"  • Signature scanning (SHA256 database)\n"
                L"  • Heuristic engine (PE, entropy, packed, macros)\n"
                L"  • Process, Network, Registry, Memory, Boot scans\n"
                L"  • Real-time file protection\n"
                L"  • Quarantine with restore/delete\n"
                L"  • Exclusion list\n"
                L"  • Scheduled scans\n"
                L"  • Drag & drop scanning\n"
                L"  • Secure file shredder\n"
                L"  • USB auto-scan\n\n"
                L"Repository: github.com/TeivrimOriginal/TDEvuris";
            MessageBoxW(hWnd, about.c_str(), L"About TDEvuris", MB_OK|MB_ICONINFORMATION);
            break;
        }
        case ID_UPDATE_BTN: {
            // Find current signatures.json path
            std::string dbPath;
            for (auto c : {std::filesystem::path(g_exeDir)/"signatures.json",
                           std::filesystem::path(g_exeDir).parent_path()/"signatures.json",
                           std::filesystem::path("./signatures.json")})
                if (std::filesystem::exists(c)) { dbPath = c.string(); break; }
            if (dbPath.empty()) dbPath = (std::filesystem::path(g_exeDir)/"signatures.json").string();

            SetWindowTextW(g_hStatus, L"Checking for signature updates...");
            g_scanThread = std::thread([dbPath]() {
                auto res = SignatureUpdater::update(
                    "https://raw.githubusercontent.com/TeivrimOriginal/TDEvuris/main/signatures.json",
                    dbPath);
                PostMessageW(g_hWnd, WM_UPDATE_DONE, res.ok ? 1 : 0, (LPARAM)new std::string(res.message));
            });
            g_scanThread.detach();
            break;
        }
        case ID_CONN_LIST_BTN: {
            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            g_scannedFiles=g_totalFiles=g_skippedFiles=0; updateStats();
            openLog(); logline(L"===== All Network Connections =====");
            enableScanCtrls(true); g_scanning = true;
            g_scanThread = std::thread([]() {
                NetworkScanner ns;
                auto conns = ns.enumConnections();
                g_countTotal = (int)conns.size();
                for (auto& c : conns) {
                    int idx = g_itemCounter++;
                    SortItem si = {}; si.idx = idx; si.status = Clean;
                    si.cols[0] = s2ws(c.procName.empty() ? ("PID:"+std::to_string(c.pid)) : c.procName);
                    si.cols[1] = L"CONN";
                    si.cols[2] = s2ws(c.remoteAddr) + L":" + std::to_wstring(c.remotePort);
                    si.cols[3] = s2ws(c.state);
                    si.cols[4] = (c.remoteAddr=="0.0.0.0" || c.remoteAddr.empty()) ? L"local" : L"remote";
                    LVITEMW lv={}; lv.mask=LVIF_TEXT|LVIF_PARAM; lv.iItem=idx;
                    lv.pszText=const_cast<wchar_t*>(si.cols[0].c_str());
                    ListView_InsertItem(g_hList,&lv);
                    for (int s=1;s<5;s++) ListView_SetItemText(g_hList,idx,s,const_cast<wchar_t*>(si.cols[s].c_str()));
                    g_sortItems.push_back(si); g_countClean++;
                }
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary{0,Scanner::isAdmin()});
            });
            g_scanThread.detach();
            break;
        }
        case ID_TOOLS_PROC_REFRESH: refreshProcesses(); break;
        case ID_TOOLS_STARTUP_REFRESH: refreshStartup(); break;
        case ID_TOOLS_PROC_KILL: {
            int sel = ListView_GetNextItem(g_hProcList, -1, LVNI_SELECTED);
            if (sel < 0) break;
            auto& [name, pid] = g_procEntries[sel];
            if (MessageBoxW(hWnd, (s2ws(name) + L" (PID " + std::to_wstring(pid) + L")\nTerminate this process?")
                            .c_str(), L"Kill Process", MB_YESNO|MB_ICONWARNING) == IDYES) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (h) { TerminateProcess(h, 1); CloseHandle(h); logline(L"[TOOLS] Killed process: " + s2ws(name)); }
                refreshProcesses();
            }
            break;
        }
        case ID_TOOLS_STARTUP_DISABLE: {
            int sel = ListView_GetNextItem(g_hStartupList, -1, LVNI_SELECTED);
            if (sel < 0) break;
            std::wstring entry = g_startupEntries[sel];
            // Format: location|name|data
            auto p1 = entry.find(L'|');
            if (p1 == std::wstring::npos) break;
            auto p2 = entry.find(L'|', p1 + 1);
            if (p2 == std::wstring::npos) break;
            std::wstring loc = entry.substr(0, p1);
            std::wstring name = entry.substr(p1 + 1, p2 - p1 - 1);
            bool isHKCU = loc.find(L"HKCU") != std::wstring::npos;
            auto subEnd = loc.find(L" [");
            std::wstring sub = loc.substr(0, subEnd);
            if (MessageBoxW(hWnd, (L"Disable startup entry:\n" + name).c_str(), L"Disable", MB_YESNO|MB_ICONQUESTION) == IDYES) {
                HKEY hk;
                if (RegOpenKeyExW(isHKCU ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                    RegDeleteValueW(hk, name.c_str());
                    RegCloseKey(hk);
                    logline(L"[TOOLS] Disabled startup: " + name);
                    refreshStartup();
                }
            }
            break;
        }
        case ID_HTMLREPORT_BTN: {
            wchar_t p[260]={}; OPENFILENAMEW ofn = {}; ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hWnd; ofn.lpstrFilter=L"HTML\0*.html\0All\0*.*\0";
            ofn.lpstrFile=p; ofn.nMaxFile=260; ofn.lpstrDefExt=L"html";
            ofn.Flags=OFN_OVERWRITEPROMPT|OFN_NOCHANGEDIR;
            if (GetSaveFileNameW(&ofn)) {
                std::ofstream f(p);
                f << "<!DOCTYPE html><html><head><meta charset='utf-8'><title>TDEvuris Report</title>";
                f << "<style>body{font-family:Segoe UI;background:#141418;color:#d7d7d7;padding:20px}"
                      "h1{color:#008cff}table{width:100%;border-collapse:collapse}"
                      "th,td{padding:6px 10px;border:1px solid #333;text-align:left}"
                      "th{background:#1e1e24}.infected{color:#ff3c3c}.heur{color:#ffb428}.clean{color:#46d246}</style></head><body>";
                f << "<h1>TDEvuris Scan Report</h1>";
                f << "<p>Generated: " << ws2s(tds()) << "</p>";
                f << "<h3>Summary</h3>";
                f << "<p>Total: " << g_countTotal << " | Infected: " << g_countInfected
                  << " | Heuristic: " << g_countHeuristic << " | Errors: " << g_countErrors << "</p>";
                f << "<table><tr><th>File</th><th>Status</th><th>Category</th><th>Threat</th><th>Conf</th></tr>";
                for (auto& item : g_sortItems) {
                    f << "<tr><td>" << ws2s(item.cols[0]) << "</td><td>" << ws2s(item.cols[1]) << "</td><td>"
                      << ws2s(item.cols[2]) << "</td><td>" << ws2s(item.cols[3]) << "</td><td>"
                      << ws2s(item.cols[4]) << "</td></tr>";
                }
                f << "</table></body></html>";
                f.close();
                logline(L"[EXPORT] HTML report: " + std::wstring(p));
                ShellExecuteW(hWnd, L"open", p, nullptr, nullptr, SW_SHOW);
            }
            break;
        }
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        auto hdc = (HDC)wP; auto hw = (HWND)lP;
        if (hw == g_hAdminLbl) { SetTextColor(hdc, RGB(255,200,50)); SetBkColor(hdc, CLR_BG); return (LRESULT)g_hBrBg; }
        if (hw == g_hDashStatus || hw == g_hDashLastScan || hw == g_hDashSigs || hw == g_hDashThreats) {
            SetTextColor(hdc, CLR_TEXT); SetBkColor(hdc, CLR_CARD); return (LRESULT)g_hBrCard;
        }
        for (int i = 0; i < 6; i++) if (hw == g_hStats[i]) { SetTextColor(hdc, CLR_TEXT); SetBkColor(hdc, CLR_PANEL); return (LRESULT)g_hBrPanel; }
        SetTextColor(hdc, CLR_TEXT); SetBkColor(hdc, CLR_BG); return (LRESULT)g_hBrBg;
    }
    case WM_CTLCOLORBTN: { SetBkColor((HDC)wP, CLR_PANEL); return (LRESULT)g_hBrPanel; }

    case WM_ERASEBKGND: { RECT r; GetClientRect(hWnd, &r); FillRect((HDC)wP, &r, g_hBrBg); return 1; }

    case WM_SCAN_PROGRESS: {
        int s = (int)wP, t = (int)lP;
        if (t > 0) SendMessageW(g_hProgress, PBM_SETPOS, (s*100)/t, 0);
        std::wstring st = L"Scanned: " + std::to_wstring(s) + L"/" + std::to_wstring(t);
        if (g_skippedFiles > 0) st += L" [skipped:" + std::to_wstring(g_skippedFiles) + L"]";
        SetWindowTextW(g_hStatus, st.c_str());
        break;
    }
    case WM_SCAN_RESULT: {
        auto* r = (ScanResult*)lP; if (r) { addResult(*r); delete r; } break;
    }
    case WM_SCAN_DONE: {
        auto* sum = (ScanSummary*)lP;
        g_scanning = false; enableScanCtrls(false);
        if (g_scanner) { delete g_scanner; g_scanner = nullptr; }
        auto msg = L"Done - " + std::to_wstring(g_countTotal) + L" files";
        if (sum) { msg += L" | Skipped(perm): " + std::to_wstring(sum->skippedAccess);
                   msg += L" | Admin: " + std::wstring(sum->admin ? L"Yes" : L"No (limited!)");
                   delete sum; }
        g_lastScanTime = tds();
        updateStats(); refreshDashboard();
        SetWindowTextW(g_hStatus, msg.c_str());
        logline(L"=== DONE ===");
        logline(L"Total:" + std::to_wstring(g_countTotal)
            + L" Infected:" + std::to_wstring(g_countInfected)
            + L" Heuristic:" + std::to_wstring(g_countHeuristic)
            + L" Skipped:" + std::to_wstring(g_skippedFiles));
        if (g_countInfected > 0) MessageBeep(MB_ICONHAND);
        if (g_countInfected + g_countHeuristic > 0) {
            trayNotify(L"TDEvuris Scan Complete",
                (L"Threats detected: " + std::to_wstring(g_countInfected + g_countHeuristic)).c_str(),
                NIIF_WARNING);
        }
        if (g_logFile.is_open()) g_logFile.close();
        break;
    }
    case WM_UPDATE_DONE: {
        auto* msg = (std::string*)lP;
        bool ok = wP != 0;
        g_scanning = false; enableScanCtrls(false);
        std::wstring msgtxt = msg ? s2ws(*msg) : std::wstring(ok ? L"done" : L"unknown error");
        if (ok) {
            // Reload signature DB
            std::string db;
            for (auto c : {std::filesystem::path(g_exeDir)/"signatures.json",
                           std::filesystem::path(g_exeDir).parent_path()/"signatures.json",
                           std::filesystem::path("./signatures.json")})
                if (std::filesystem::exists(c)) { db = c.string(); break; }
            g_sigdb.load(db);
            auto t = L"TDEvuris - " + std::to_wstring(g_sigdb.count()) + L" sigs" +
                     (Scanner::isAdmin() ? L" [ADMIN]" : L" [USER]");
            SetWindowTextW(hWnd, t.c_str());
            SetWindowTextW(g_hSetSigCount, (L"Loaded signatures: " + std::to_wstring(g_sigdb.count())).c_str());
            refreshDashboard();
            logline(L"[UPDATE] " + msgtxt);
            trayNotify(L"TDEvuris Update", msgtxt, NIIF_INFO);
        } else {
            logline(L"[UPDATE] FAILED: " + msgtxt);
        }
        if (msg) delete msg;
        SetWindowTextW(g_hStatus, (L"Update: " + msgtxt).c_str());
        break;
    }
    case WM_DASH_UPDATE:
        refreshDashboard();
        break;

    case WM_TIMER: {
        if (wP == g_scheduleTimer && !g_scanning) {
            PostMessageW(hWnd, WM_COMMAND, ID_QUICKSCAN_BTN, 0);
        }
        break;
    }

    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wP;
        UINT count = DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0);
        if (count > 0) {
            // Switch to scan tab
            TabCtrl_SetCurSel(g_hTab, 1);
            ShowWindow(g_hDashPanel, SW_HIDE); ShowWindow(g_hQuarPanel, SW_HIDE);
            ShowWindow(g_hToolsPanel, SW_HIDE); ShowWindow(g_hSetPanel, SW_HIDE);
            ShowWindow(g_hScanPanel, SW_SHOW);

            g_itemCounter = 0; g_sortItems.clear();
            ListView_DeleteAllItems(g_hList);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            g_scannedFiles=g_totalFiles=g_skippedFiles=0;
            g_countTotal=g_countClean=g_countInfected=g_countHeuristic=g_countErrors=0;
            updateStats(); openLog();
            logline(L"===== Dropped Files Scan (" + std::to_wstring(count) + L" items) =====");
            enableScanCtrls(true); g_scanning = true;

            std::vector<std::wstring> paths;
            for (UINT i = 0; i < count; i++) {
                wchar_t p[MAX_PATH];
                DragQueryFileW(hDrop, i, p, MAX_PATH);
                paths.push_back(p);
            }
            DragFinish(hDrop);

            g_scanThread = std::thread([paths]() {
                int total = (int)paths.size();
                int scanned = 0;
                g_scanner = new Scanner(g_sigdb);
                for (auto& wp : paths) {
                    std::string p = ws2s(wp);
                    // Check if directory
                    DWORD attr = GetFileAttributesW(wp.c_str());
                    if (attr == INVALID_FILE_ATTRIBUTES) continue;
                    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
                        auto sum = g_scanner->scanDirectory(p, nullptr, [&](const ScanResult& r) {
                            if (isExcluded(s2ws(r.filepath))) return;
                            PostMessageW(g_hWnd, WM_SCAN_RESULT, 0, (LPARAM)new ScanResult(r));
                        });
                        scanned += sum.scannedFiles;
                    } else {
                        auto r = g_scanner->scanFile(p);
                        if (!isExcluded(wp)) PostMessageW(g_hWnd, WM_SCAN_RESULT, 0, (LPARAM)new ScanResult(r));
                        scanned++;
                    }
                    g_totalFiles = total;
                    g_scannedFiles = scanned;
                    PostMessageW(g_hWnd, WM_SCAN_PROGRESS, scanned, total);
                }
                ScanSummary ss; ss.totalFiles = total; ss.scannedFiles = scanned; ss.admin = Scanner::isAdmin();
                PostMessageW(g_hWnd, WM_SCAN_DONE, 0, (LPARAM)new ScanSummary(ss));
            });
            g_scanThread.detach();
            break;
        }
    }

    case WM_DEVICECHANGE: {
        if (wP == DBT_DEVICEARRIVAL) {
            auto* dbh = (DEV_BROADCAST_HDR*)lP;
            if (dbh && dbh->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                auto* dv = (DEV_BROADCAST_VOLUME*)dbh;
                wchar_t drive = L'A';
                for (int i = 0; i < 26; i++) {
                    if (dv->dbcv_unitmask & (1 << i)) {
                        drive = L'A' + i;
                        std::wstring root = std::wstring(1, drive) + L":\\";
                        if (GetDriveTypeW(root.c_str()) == DRIVE_REMOVABLE) {
                            logline(L"[USB] Detected: " + root);
                            // Auto-scan USB
                            PostMessageW(g_hWnd, WM_USB_ARRIVAL, 0, (LPARAM)(new std::wstring(root)));
                        }
                    }
                }
            }
        }
        break;
    }

    case WM_USB_ARRIVAL: {
        auto* root = (std::wstring*)lP;
        if (root) {
            g_lastUsbScanned = *root;
            logline(L"[USB] Auto-scanning: " + *root);
            PostMessageW(g_hWnd, WM_COMMAND, ID_QUICKSCAN_BTN, 0);
            SetWindowTextW(g_hStatus, (L"USB auto-scan: " + *root).c_str());
            delete root;
        }
        break;
    }

    case WM_WATCHER_EVENT: {
        auto* path = (std::wstring*)wP;
        if (path) {
            auto f = *path;
            logline(L"[RTP] Modified: " + f);
            // Scan the file via callback chain if not excluded
            if (!isExcluded(f) && g_rtpEnabled) {
                std::string fp = ws2s(f);
                // Quick async hash check
                g_scanThread = std::thread([fp]() {
                    std::string hash = Hasher::sha256(fp);
                    if (!hash.empty()) {
                        auto sig = g_sigdb.match(hash);
                        if (sig) {
                            ScanResult r;
                            r.filepath = fp;
                            r.status = SignatureMatch;
                            r.threatName = sig->name;
                            r.category = sig->category;
                            r.confidence = 1.0;
                            PostMessageW(g_hWnd, WM_SCAN_RESULT, 0, (LPARAM)new ScanResult(r));
                            // Auto-quarantine detected RTP threat
                            std::wstring wfp = s2ws(fp);
                            std::wstring quarDir = s2ws(g_exeDir) + L"\\quarantine";
                            CreateDirectoryW(quarDir.c_str(), nullptr);
                            auto fn = wfp.substr(wfp.rfind(L'\\')+1);
                            std::wstring dest = quarDir + L"\\" + fn + L".quar";
                            if (MoveFileW(wfp.c_str(), dest.c_str()))
                                PostMessageW(g_hWnd, WM_QUARANTINED, 0, (LPARAM)new std::wstring(dest));
                        }
                    }
                });
                g_scanThread.detach();
            }
            delete path;
        }
        break;
    }

    case WM_TRAY_ICON: {
        if (lP == WM_LBUTTONDBLCLK) { ShowWindow(hWnd, SW_SHOW); SetForegroundWindow(hWnd); }
        if (lP == WM_RBUTTONUP) {
            POINT p; GetCursorPos(&p);
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, 3001, L"Show");
            AppendMenuW(m, MF_STRING, 3002, L"Quick Scan");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, 3003, L"Exit");
            int cmd = TrackPopupMenu(m, TPM_RETURNCMD|TPM_NONOTIFY, p.x,p.y,0,hWnd,nullptr);
            DestroyMenu(m);
            if (cmd == 3001) { ShowWindow(hWnd, SW_SHOW); SetForegroundWindow(hWnd); }
            if (cmd == 3002) PostMessageW(hWnd, WM_COMMAND, ID_QUICKSCAN_BTN, 0);
            if (cmd == 3003) PostMessageW(hWnd, WM_CLOSE, 0, 0);
        }
        break;
    }

    case WM_SIZE: {
        RECT r; GetClientRect(hWnd, &r);
        if (g_hTab) SetWindowPos(g_hTab, nullptr, 0,0,r.right,r.bottom, SWP_NOZORDER);
        RECT tr; GetClientRect(g_hTab, &tr);
        TabCtrl_AdjustRect(g_hTab, FALSE, &tr);
        int ww = tr.right - tr.left;
        int wh = tr.bottom - tr.top;
        if (g_hDashPanel) SetWindowPos(g_hDashPanel, nullptr, tr.left,tr.top,ww,wh, SWP_NOZORDER);
        if (g_hScanPanel) SetWindowPos(g_hScanPanel, nullptr, tr.left,tr.top,ww,wh, SWP_NOZORDER);
        if (g_hQuarPanel) SetWindowPos(g_hQuarPanel, nullptr, tr.left,tr.top,ww,wh, SWP_NOZORDER);
        if (g_hToolsPanel) SetWindowPos(g_hToolsPanel, nullptr, tr.left,tr.top,ww,wh, SWP_NOZORDER);
        if (g_hSetPanel)  SetWindowPos(g_hSetPanel,  nullptr, tr.left,tr.top,ww,wh, SWP_NOZORDER);
        if (g_hStatus) SendMessageW(g_hStatus, WM_SIZE, 0, 0);
        if (g_hList) {
            SetWindowPos(g_hList, nullptr, 10, 188, ww-24, wh-210, SWP_NOZORDER);
            LVCOLUMNW lc = {}; lc.mask = LVCF_WIDTH; lc.cx = ww - 330;
            if (lc.cx < 100) lc.cx = 100;
            ListView_SetColumnWidth(g_hList, 0, lc.cx);
        }
        if (g_hProgress) SetWindowPos(g_hProgress, nullptr, 12, 58, ww-24, 14, SWP_NOZORDER);
        if (g_hDriveCombo) SetWindowPos(g_hDriveCombo, nullptr, 60, 28, 140, 200, SWP_NOZORDER);
        if (g_hQuarList) SetWindowPos(g_hQuarList, nullptr, 12,12,ww-24,250, SWP_NOZORDER);
        break;
    }

    case WM_CLOSE:
        if (g_minimizeToTray) {
            ShowWindow(hWnd, SW_HIDE);
            return 0;
        }
        if (g_scanning && g_scanner) g_scanner->stop();
        g_watcher.stop();
        if (g_scheduleTimer) { KillTimer(hWnd, g_scheduleTimer); g_scheduleTimer = 0; }
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY: {
        DeleteObject(g_hFont); DeleteObject(g_hFontBold); DeleteObject(g_hFontLarge);
        DeleteObject(g_hBrBg); DeleteObject(g_hBrPanel); DeleteObject(g_hBrCard);
        if (g_logFile.is_open()) g_logFile.close();
        DeleteCriticalSection(&g_logCs);
        NOTIFYICONDATAW nd = {sizeof(nd), g_hWnd, 1, NIM_DELETE};
        Shell_NotifyIconW(NIM_DELETE, &nd);
        PostQuitMessage(0);
        break;
    }
    default: return DefWindowProcW(hWnd, msg, wP, lP);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int cShow) {
    g_hInst = hInst;

    AllocConsole();
    SetConsoleTitleW(L"TDEvuris Console");
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hCon && hCon != INVALID_HANDLE_VALUE) {
        DWORD m; GetConsoleMode(hCon, &m); m |= ENABLE_VIRTUAL_TERMINAL_PROCESSING; SetConsoleMode(hCon, m);
        DWORD w; WriteConsoleW(hCon, L"\x1b[94mTDEvuris v2.0\x1b[0m - Console\n========================\n", 50, &w, nullptr);
    }

    InitializeCriticalSection(&g_logCs);

    wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH);
    g_exeDir = ws2s(p);
    auto pos = g_exeDir.rfind('\\'); if (pos != std::wstring::npos) g_exeDir = g_exeDir.substr(0, pos);

    INITCOMMONCONTROLSEX ic = {}; ic.dwSize = sizeof(ic); ic.dwICC = ICC_STANDARD_CLASSES|ICC_PROGRESS_CLASS|ICC_LISTVIEW_CLASSES|ICC_BAR_CLASSES|ICC_TAB_CLASSES;
    InitCommonControlsEx(&ic);

    WNDCLASSW wc = {}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.hCursor = LoadCursor(nullptr,IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(CLR_BG); wc.lpszClassName = L"TDEvurisClass";
    RegisterClassW(&wc);

    g_hWnd = CreateWindowW(L"TDEvurisClass", L"TDEvuris",
        WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN, CW_USEDEFAULT,CW_USEDEFAULT,780,560,
        nullptr,nullptr,hInst,nullptr);
    if (!g_hWnd) return 1;
    DragAcceptFiles(g_hWnd, TRUE);
    ShowWindow(g_hWnd, cShow); UpdateWindow(g_hWnd);

    // Tray icon
    NOTIFYICONDATAW nd = {sizeof(nd)};
    nd.hWnd = g_hWnd; nd.uID = 1; nd.uFlags = NIF_MESSAGE|NIF_ICON|NIF_TIP;
    nd.uCallbackMessage = WM_TRAY_ICON;
    nd.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wcsncpy(nd.szTip, L"TDEvuris Antivirus", 128);
    Shell_NotifyIconW(NIM_ADD, &nd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
