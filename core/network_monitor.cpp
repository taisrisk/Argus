#include "network_monitor.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace argus {

NetworkMonitor::NetworkMonitor() 
    : is_active_(false) {
    whitelist_.insert("google.com");
    whitelist_.insert("googleapis.com");
    whitelist_.insert("gstatic.com");
    whitelist_.insert("mozilla.org");
    whitelist_.insert("mozilla.net");
    whitelist_.insert("microsoft.com");
    whitelist_.insert("windows.com");
}

NetworkMonitor::~NetworkMonitor() {
    if (is_active_) {
        Shutdown();
    }
}

bool NetworkMonitor::Initialize() {
    if (is_active_) {
        return false;
    }
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    is_active_ = true;
    last_scan_ = std::chrono::system_clock::now();
    
    return true;
}

void NetworkMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    events_.clear();
    tracked_pids_.clear();
    
    WSACleanup();
}

void NetworkMonitor::Update() {
    if (!is_active_) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_scan_).count();
    
    if (elapsed >= 10) {
        ScanConnections();
        last_scan_ = now;
    }
}

std::vector<NetworkEvent> NetworkMonitor::GetRecentEvents(int max_count) {
    if (events_.size() <= static_cast<size_t>(max_count)) {
        return events_;
    }
    
    return std::vector<NetworkEvent>(events_.end() - max_count, events_.end());
}

void NetworkMonitor::SetTrackedProcesses(const std::vector<uint32_t>& pids) {
    tracked_pids_ = pids;
}

void NetworkMonitor::ScanConnections() {
    if (tracked_pids_.empty()) {
        return;
    }
    
    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    DWORD size = 0;
    
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    
    if (tcpTable && GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            uint32_t pid = tcpTable->table[i].dwOwningPid;
            
            if (std::find(tracked_pids_.begin(), tracked_pids_.end(), pid) != tracked_pids_.end()) {
                NetworkEvent event;
                event.timestamp = std::chrono::system_clock::now();
                event.process_id = pid;
                event.type = ConnectionType::TCP;
                
                struct in_addr addr;
                addr.S_un.S_addr = tcpTable->table[i].dwRemoteAddr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                event.remote_address = ip_str;
                event.remote_port = ntohs((u_short)tcpTable->table[i].dwRemotePort);
                
                if (IsWhitelisted(event.remote_address)) {
                    continue;
                }
                
                if (IsBlacklisted(event.remote_address)) {
                    event.is_suspicious = true;
                    event.context = "Blacklisted destination";
                } else if (IsSuspiciousPattern(event)) {
                    event.is_suspicious = true;
                    event.context = "Suspicious connection pattern";
                } else {
                    event.is_suspicious = false;
                    event.context = "Unknown destination";
                }
                
                events_.push_back(event);
            }
        }
    }
    
    if (tcpTable) {
        free(tcpTable);
    }
}

bool NetworkMonitor::IsWhitelisted(const std::string& address) {
    for (const auto& domain : whitelist_) {
        if (address == domain || address.find("." + domain) != std::string::npos || address.find(domain + ".") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool NetworkMonitor::IsBlacklisted(const std::string& address) {
    for (const auto& domain : blacklist_) {
        if (address == domain || address.find("." + domain) != std::string::npos || address.find(domain + ".") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool NetworkMonitor::IsSuspiciousPattern(const NetworkEvent& event) {
    if (event.remote_port == 4444 || event.remote_port == 5555) {
        return true;
    }
    
    return false;
}

}
