#pragma once
#include <string>
#include <vector>

struct HeuristicResult {
    std::string name;
    std::string category;
    double confidence;
};

class HeuristicsEngine {
public:
    std::vector<HeuristicResult> analyze(const std::string& filepath);
};
