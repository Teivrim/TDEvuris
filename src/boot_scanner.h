#pragma once
#include <string>
#include <vector>

struct BootResult {
    std::string device;
    std::string threatName;
    std::string category;
    double confidence = 0.0;
    bool suspicious = false;
    std::string details;
};

class BootScanner {
public:
    std::vector<BootResult> scanMBR();
    std::vector<BootResult> scanAll();
};
