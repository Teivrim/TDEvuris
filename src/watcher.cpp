#include "watcher.h"
#include <vector>
#include <algorithm>

FileWatcher::FileWatcher() {
    m_overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}
FileWatcher::~FileWatcher() {
    stop();
    if (m_overlapped.hEvent) CloseHandle(m_overlapped.hEvent);
}

std::wstring FileWatcher::getDriveRoot(const std::wstring& path) {
    wchar_t root[4] = {path[0], L':', L'\\', 0};
    return root;
}

bool FileWatcher::start(const std::wstring& directory, Callback cb) {
    if (m_running) return false;
    m_directory = directory;
    m_callback = cb;
    m_running = true;
    m_hThread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* self = (FileWatcher*)p;
        self->watchThread(self->getDriveRoot(self->m_directory));
        return 0;
    }, this, 0, nullptr);
    return m_hThread != nullptr;
}

void FileWatcher::stop() {
    m_running = false;
    if (m_hDir != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_hDir, &m_overlapped);
        CloseHandle(m_hDir);
        m_hDir = INVALID_HANDLE_VALUE;
    }
    if (m_hThread) {
        WaitForSingleObject(m_hThread, 1000);
        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
}

void FileWatcher::watchThread(const std::wstring& directory) {
    m_hDir = CreateFileW(directory.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);

    if (m_hDir == INVALID_HANDLE_VALUE) { m_running = false; return; }

    DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION |
                   FILE_NOTIFY_CHANGE_SIZE;

    while (m_running) {
        ZeroMemory(m_buffer, sizeof(m_buffer));
        DWORD bytes = 0;
        if (!ReadDirectoryChangesW(m_hDir, m_buffer, sizeof(m_buffer), TRUE,
                                    filter, &bytes, &m_overlapped, nullptr)) {
            break;
        }
        DWORD wait = WaitForSingleObject(m_overlapped.hEvent, 500);
        if (wait == WAIT_TIMEOUT) continue;
        if (!m_running) break;

        DWORD transferred;
        GetOverlappedResult(m_hDir, &m_overlapped, &transferred, FALSE);

        FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)m_buffer;
        while (true) {
            std::wstring name(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
            std::wstring fullPath = directory + name;

            if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED) {
                // Skip directories
                DWORD attrs = GetFileAttributesW(fullPath.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (m_callback) m_callback(fullPath, fni->Action);
                }
            }

            if (fni->NextEntryOffset == 0) break;
            fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
        }

        ResetEvent(m_overlapped.hEvent);
    }
    m_running = false;
}
