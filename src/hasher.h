#pragma once
#include <string>
#include <vector>
#include <cstdint>

class Hasher {
public:
    static std::string sha256(const std::string& filepath);
    static std::string sha256(const std::vector<uint8_t>& data);
};
