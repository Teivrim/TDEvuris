#pragma once
#include <string>
#include <vector>

struct NetConnection {
    std::string localAddr;
    int localPort = 0;
    std::string remoteAddr;
    int remotePort = 0;
    int pid = 0;
    std::string procName;
    std::string state;
};

struct NetResult {
    NetConnection conn;
    std::string threatName;
    std::string category;
    double confidence = 0.0;
    bool suspicious = false;
};

class NetworkScanner {
public:
    std::vector<NetConnection> enumConnections();
    std::vector<NetResult> analyze();
};
