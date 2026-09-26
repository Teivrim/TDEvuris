#include "shredder.h"
#include <windows.h>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <algorithm>

bool Shredder::shred(const std::wstring& filepath, int passes) {
    HANDLE h = CreateFileW(filepath.c_str(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li;
    GetFileSizeEx(h, &li);
    LONGLONG size = li.QuadPart;

    if (size == 0) { CloseHandle(h); return true; }

    // Buffer up to 64KB
    DWORD bufSize = (DWORD)std::min(size, (LONGLONG)65536);
    std::vector<BYTE> buffer(bufSize);

    srand((unsigned int)time(nullptr));

    for (int pass = 0; pass < passes; pass++) {
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);

        BYTE fill;
        switch (pass % 3) {
            case 0: fill = 0x00; break; // All zeros
            case 1: fill = 0xFF; break; // All ones
            case 2:                     // Random
                for (auto& b : buffer) b = (BYTE)(rand() % 256);
                break;
        }

        if (pass % 3 != 2) memset(buffer.data(), fill, bufSize);

        LONGLONG remaining = size;
        while (remaining > 0) {
            DWORD toWrite = (DWORD)std::min((LONGLONG)bufSize, remaining);
            DWORD written;
            if (!WriteFile(h, buffer.data(), toWrite, &written, nullptr)) {
                CloseHandle(h);
                return false;
            }
            remaining -= written;
        }
        FlushFileBuffers(h);
    }

    CloseHandle(h);
    return true;
}

bool Shredder::shredAndDelete(const std::wstring& filepath, int passes) {
    if (!shred(filepath, passes)) return false;
    return DeleteFileW(filepath.c_str()) != 0;
}
