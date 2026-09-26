#include "signatures.h"
#include "json.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

static bool ieq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(),
        [](char ca, char cb) {
            return std::tolower(static_cast<unsigned char>(ca)) ==
                   std::tolower(static_cast<unsigned char>(cb));
        });
}

bool SignatureDB::load(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) return false;

    std::stringstream ss;
    ss << file.rdbuf();
    file.close();

    auto json = simple_json::parse(ss.str());
    if (json.type != simple_json::JsonValue::Array) return false;

    for (const auto& elem : json.arr) {
        SignatureEntry entry;
        entry.name        = elem.get("name").asString();
        entry.hash        = elem.get("hash").asString();
        entry.category    = elem.get("category").asString("unknown");
        entry.description = elem.get("description").asString();
        if (!entry.name.empty() && !entry.hash.empty())
            m_entries.push_back(std::move(entry));
    }
    return true;
}

const SignatureEntry* SignatureDB::match(const std::string& hash) const {
    for (const auto& e : m_entries) {
        if (ieq(hash, e.hash))
            return &e;
    }
    return nullptr;
}

size_t SignatureDB::count() const {
    return m_entries.size();
}
