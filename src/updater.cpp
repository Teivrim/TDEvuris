#include "updater.h"
#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <sstream>
#include <cstdio>

#pragma comment(lib, "wininet.lib")

bool SignatureUpdater::downloadFile(const std::string& url, const std::string& targetPath, std::string& err) {
    HINTERNET hNet = InternetOpenW(L"TDEvurisUpdater/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hNet) { err = "InternetOpen failed: " + std::to_string(GetLastError()); return false; }

    HINTERNET hUrl = InternetOpenUrlA(hNet, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) {
        err = "InternetOpenUrl failed: " + std::to_string(GetLastError());
        InternetCloseHandle(hNet);
        return false;
    }

    std::ofstream f(targetPath, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        err = "Cannot write target file";
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hNet);
        return false;
    }

    char buf[8192];
    DWORD read;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0) {
        f.write(buf, read);
    }

    f.close();
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    return true;
}

UpdateResult SignatureUpdater::update(const std::string& url, const std::string& targetPath) {
    UpdateResult result;

    // Count current signatures (old) by reading the existing file
    std::ifstream in(targetPath, std::ios::binary);
    if (in.is_open()) {
        std::stringstream ss;
        ss << in.rdbuf();
        std::string content = ss.str();
        // Rough count: number of "hash" occurrences
        size_t pos = 0, count = 0;
        while ((pos = content.find("\"hash\"", pos)) != std::string::npos) { count++; pos += 6; }
        result.oldCount = (int)count;
        in.close();
    }

    std::string err;
    if (!downloadFile(url, targetPath + ".tmp", err)) {
        result.message = "Download failed: " + err;
        return result;
    }

    // Validate the downloaded file (must be valid JSON array)
    std::ifstream tmp(targetPath + ".tmp", std::ios::binary);
    if (!tmp.is_open()) { result.message = "Cannot read downloaded file"; return result; }
    std::stringstream ss; ss << tmp.rdbuf(); tmp.close();
    std::string content = ss.str();

    // Simple sanity check
    if (content.size() < 10 || content.find('[') == std::string::npos) {
        result.message = "Downloaded file is not valid JSON";
        std::remove((targetPath + ".tmp").c_str());
        return result;
    }

    // Count new signatures
    size_t pos = 0, count = 0;
    while ((pos = content.find("\"hash\"", pos)) != std::string::npos) { count++; pos += 6; }
    result.newCount = (int)count;

    // Move temp into place
    if (std::remove(targetPath.c_str()) != 0) {}
    if (std::rename((targetPath + ".tmp").c_str(), targetPath.c_str()) != 0) {
        result.message = "Cannot replace signature file";
        return result;
    }

    result.ok = true;
    result.newSigs = result.newCount > 0;
    result.message = "Updated: " + std::to_string(result.oldCount) + " -> " + std::to_string(result.newCount);
    return result;
}
