#pragma once
#include <string>
#include <vector>

struct SignatureEntry {
    std::string name;
    std::string hash;
    std::string category;
    std::string description;
};

class SignatureDB {
public:
    bool load(const std::string& filepath);
    const SignatureEntry* match(const std::string& hash) const;
    size_t count() const;

private:
    std::vector<SignatureEntry> m_entries;
};
