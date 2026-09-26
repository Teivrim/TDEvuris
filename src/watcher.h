#pragma once
#include <windows.h>
#include <string>
#include <functional>

class FileWatcher {
public:
    using Callback = std::function<void(const std::wstring& path, DWORD action)>;

    FileWatcher();
    ~FileWatcher();

    bool start(const std::wstring& directory, Callback cb);
    void stop();
    bool isRunning() const { return m_running; }

private:
    void watchThread(const std::wstring& directory);
    std::wstring getDriveRoot(const std::wstring& path);

    std::wstring m_directory;
    HANDLE m_hDir = INVALID_HANDLE_VALUE;
    HANDLE m_hThread = nullptr;
    bool m_running = false;
    Callback m_callback;
    OVERLAPPED m_overlapped = {};
    char m_buffer[65536];
};
