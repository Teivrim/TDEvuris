#pragma once
#include <string>
#include <vector>
#include <functional>
#include "signatures.h"
#include "heuristics.h"

enum ScanStatus { Clean, SignatureMatch, HeuristicMatch, Error };

struct ScanResult {
    std::string filepath;
    ScanStatus status = Clean;
    std::string threatName;
    std::string category;
    std::string description;
    double confidence = 0.0;
};

struct ScanSummary {
    int totalFiles = 0;
    int scannedFiles = 0;
    int skippedAccess = 0;
    int clean = 0;
    int infected = 0;
    int heuristic = 0;
    int errors = 0;
    bool admin = false;
    std::string errorDir;
};

class Scanner {
public:
    explicit Scanner(const SignatureDB& sigdb);

    using ProgressCb = std::function<void(const std::string& file,
                                          int scanned, int total,
                                          int skipped, const std::string& status)>;
    using ResultCb  = std::function<void(const ScanResult&)>;

    ScanSummary scanDirectory(const std::string& dirpath,
                               const ProgressCb& onProgress = nullptr,
                               const ResultCb& onResult = nullptr);
    ScanSummary scanProcesses(const ProgressCb& onProgress = nullptr,
                               const ResultCb& onResult = nullptr);
    ScanResult scanFile(const std::string& filepath);
    static bool isAdmin();
    void stop();

private:
    void preCount(const std::string& dirpath, int& total, int& denied);
    const SignatureDB& m_sigdb;
    HeuristicsEngine m_heur;
    bool m_stopped = false;
};
