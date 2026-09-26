#pragma once
#include <string>

struct UpdateResult {
    bool ok = false;
    bool newSigs = false;
    int oldCount = 0;
    int newCount = 0;
    std::string message;
};

class SignatureUpdater {
public:
    // Downloads signatures.json from the given URL into the target path.
    static UpdateResult update(const std::string& url, const std::string& targetPath);
    static bool downloadFile(const std::string& url, const std::string& targetPath, std::string& err);
};
