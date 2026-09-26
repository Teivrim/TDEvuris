#pragma once
#include <string>
#include <vector>

struct RegEntry {
    std::string key;
    std::string value;
    std::string data;
    std::string category; // autorun, service, browser_plugin, etc
};

struct RegResult {
    RegEntry entry;
    std::string threatName;
    std::string threatCategory;
    double confidence = 0.0;
    bool suspicious = false;
};

class RegistryScanner {
public:
    std::vector<RegEntry> enumAutoruns();
    std::vector<RegResult> analyze();
};
