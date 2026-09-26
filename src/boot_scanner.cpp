#include "boot_scanner.h"
// NOMINMAX: без этого windows.h определяет min/max как макросы,
// и любой вызов std::min/std::max не компилируется (MSVC C2589).
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <vector>
#include <cstring>

static bool readSector(const std::wstring& device, BYTE* buffer, DWORD size, DWORD sectorOffset = 0) {
    HANDLE h = CreateFileW(device.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)sectorOffset * 512;
    SetFilePointerEx(h, li, nullptr, FILE_BEGIN);

    DWORD read;
    BOOL ok = ReadFile(h, buffer, size, &read, nullptr);
    CloseHandle(h);
    return ok && read == size;
}

// Known bootkit signatures in MBR
struct BootSig {
    const char* name;
    const char* category;
    int offset;
    int len;
    const BYTE* pattern;
    double confidence;
};

static const BYTE petya_mbr[] = {0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x8E, 0xD8};
static const BYTE stoned_mbr[] = {0xFA, 0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C};
static const BYTE satana_mbr[] = {0x31, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFB};

static std::vector<BootSig> g_bootSigs = {
    {"NotPetya.MBR", "ransomware", 0, (int)sizeof(petya_mbr), petya_mbr, 0.95},
    {"Stoned.MBR", "bootkit", 0, (int)sizeof(stoned_mbr), stoned_mbr, 0.85},
    {"Satana.MBR", "ransomware", 0, (int)sizeof(satana_mbr), satana_mbr, 0.85},
};

static bool matchPattern(const BYTE* data, const BootSig& sig) {
    for (int i = 0; i < sig.len; i++)
        if (data[sig.offset + i] != (BYTE)sig.pattern[i]) return false;
    return true;
}

std::vector<BootResult> BootScanner::scanMBR() {
    std::vector<BootResult> results;
    BYTE mbr[512];

    if (!readSector(L"\\\\.\\PHYSICALDRIVE0", mbr, sizeof(mbr))) return results;

    // Check for valid MBR signature (55 AA at end)
    if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
        BootResult r;
        r.device = "PHYSICALDRIVE0";
        r.threatName = "Boot.InvalidMBR";
        r.category = "rootkit";
        r.confidence = 0.7;
        r.suspicious = true;
        r.details = "Invalid MBR signature (missing 55 AA)";
        results.push_back(r);
        return results;
    }

    // Match known bootkits
    for (auto& sig : g_bootSigs) {
        if (matchPattern(mbr, sig)) {
            BootResult r;
            r.device = "PHYSICALDRIVE0";
            r.threatName = sig.name;
            r.category = sig.category;
            r.confidence = sig.confidence;
            r.suspicious = true;
            char buf[256];
            snprintf(buf, sizeof(buf), "MBR bootkit pattern at offset 0x%X", sig.offset);
            r.details = buf;
            results.push_back(r);
        }
    }

    // Check for unusual MBR code (most MBRs are very short, just loading VBR)
    // If code section has too many non-zero bytes, flag it
    int nonZero = 0;
    for (int i = 0; i < 440; i++) if (mbr[i] != 0) nonZero++;
    if (nonZero > 300) {
        BootResult r;
        r.device = "PHYSICALDRIVE0";
        r.threatName = "Boot.SuspiciousMBR";
        r.category = "suspicious";
        r.confidence = 0.4;
        r.suspicious = true;
        r.details = "Unusually large MBR code section (" + std::to_string(nonZero) + " non-zero bytes)";
        results.push_back(r);
    }

    return results;
}

std::vector<BootResult> BootScanner::scanAll() {
    return scanMBR();
}
