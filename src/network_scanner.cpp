#include "network_scanner.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <map>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static std::string ipStr(DWORD ip) {
    in_addr a; a.S_un.S_addr = ip;
    char b[32]; inet_ntop(AF_INET, &a, b, sizeof(b)); return b;
}

static std::string getProcName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::to_string(pid);
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    std::string name;
    if (Process32FirstW(snap, &pe)) do {
        if (pe.th32ProcessID == pid) {
            int l = WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,nullptr,0,nullptr,nullptr);
            name.resize(l-1);
            WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,name.data(),l,nullptr,nullptr);
            break;
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return name.empty() ? std::to_string(pid) : name;
}

static bool isSuspiciousPort(int port) {
    switch (port) {
        case 4444: case 5555: case 6666: case 6667: case 6668:
        case 6669: case 1337: case 31337: case 12345: case 12346:
        case 20034: case 27374: case 31338: case 54321: case 4321:
        case 8080: case 8081: case 9001: case 9002: case 4443:
        case 8484: case 11000: case 11001: case 14664: case 16969:
        case 17185: case 19191: case 23476: case 23477: case 24339:
        case 25252: case 30102: case 30103: case 31339: case 34012:
        case 34112: case 45576: case 51105: case 65000: case 65535:
            return true;
    }
    return false;
}

static bool isKnownBadIP(const std::string& ip) {
    (void)ip;
    // Could check against known malicious IPs
    return false;
}

std::vector<NetConnection> NetworkScanner::enumConnections() {
    std::vector<NetConnection> result;

    ULONG sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<MIB_TCPROW_OWNER_PID> table(sz / sizeof(MIB_TCPROW_OWNER_PID));
    if (GetExtendedTcpTable(table.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return result;

    int count = sz / sizeof(MIB_TCPROW_OWNER_PID);
    for (int i = 0; i < count; i++) {
        auto& r = table[i];
        NetConnection nc;
        nc.localAddr  = ipStr(r.dwLocalAddr);
        nc.localPort  = ntohs((u_short)r.dwLocalPort);
        nc.remoteAddr = ipStr(r.dwRemoteAddr);
        nc.remotePort = ntohs((u_short)r.dwRemotePort);
        nc.pid = r.dwOwningPid;
        nc.procName = getProcName(r.dwOwningPid);

        static const char* states[] = {"?", "CLOSED","LISTEN","SYN_SENT","SYN_RCVD",
            "ESTABLISHED","FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT","CLOSING","LAST_ACK","TIME_WAIT"};
        nc.state = (r.dwState < 12) ? states[r.dwState] : "?";

        if (r.dwRemoteAddr != 0)
            result.push_back(nc);
    }
    return result;
}

std::vector<NetResult> NetworkScanner::analyze() {
    std::vector<NetResult> results;
    auto conns = enumConnections();

    std::map<std::string, int> connCount;
    for (auto& c : conns) connCount[c.remoteAddr]++;

    for (auto& c : conns) {
        NetResult nr;
        nr.conn = c;
        nr.suspicious = false;

        // Check suspicious remote ports
        if (isSuspiciousPort(c.remotePort)) {
            nr.threatName = "Net.Conn.SuspiciousPort:" + std::to_string(c.remotePort);
            nr.category = "trojan";
            nr.confidence = 0.6;
            nr.suspicious = true;
        }

        // Check connections to many different IPs from same process
        if (connCount[c.remoteAddr] > 10 && c.remoteAddr != "0.0.0.0") {
            nr.threatName = "Net.Conn.MultipleOutbound";
            nr.category = "botnet";
            nr.confidence = 0.5;
            nr.suspicious = true;
        }

        // High port outbound
        if (c.remotePort > 50000 && c.localPort < 1024) {
            nr.threatName = "Net.Conn.HighPortOutbound";
            nr.category = "suspicious";
            nr.confidence = 0.4;
            nr.suspicious = true;
        }

        if (nr.suspicious)
            results.push_back(nr);
    }
    return results;
}
