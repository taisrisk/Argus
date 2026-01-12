#include "network_monitor.h"

// Prevent winsock.h from being pulled in by windows.h (possibly via headers).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <cctype>

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

                // Fast allow-list: local/private IPv4 should not be treated as exfil.
                if (IsPrivateOrLoopbackIPv4(event.remote_address)) {
                    continue;
                }

                // Best-effort: resolve IP -> hostname (cached) so domain whitelist can work.
                // If resolution fails, we keep using the IP string.
                std::string resolved_host = TryResolveRemoteHostCached(event.remote_address);
                
                if (IsWhitelisted(resolved_host.empty() ? event.remote_address : resolved_host)) {
                    continue;
                }
                
                if (IsBlacklisted(resolved_host.empty() ? event.remote_address : resolved_host)) {
                    event.is_suspicious = true;
                    event.context = "Blacklisted destination";
                } else if (IsSuspiciousPattern(event)) {
                    event.is_suspicious = true;
                    event.context = "Suspicious connection pattern";
                } else {
                    event.is_suspicious = false;
                    event.context = resolved_host.empty() ? "Unknown destination" : ("Unknown destination: " + resolved_host);
                }
                
                events_.push_back(event);
            }
        }
    }
    
    if (tcpTable) {
        free(tcpTable);
    }
}

static std::string ToLowerAscii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

bool NetworkMonitor::IsPrivateOrLoopbackIPv4(const std::string& ip) {
    IN_ADDR addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }

    uint32_t host = ntohl(addr.S_un.S_addr);
    uint8_t a = static_cast<uint8_t>((host >> 24) & 0xFF);
    uint8_t b = static_cast<uint8_t>((host >> 16) & 0xFF);

    // 127.0.0.0/8 loopback
    if (a == 127) return true;
    // 10.0.0.0/8
    if (a == 10) return true;
    // 172.16.0.0/12
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    // 192.168.0.0/16
    if (a == 192 && b == 168) return true;
    // 169.254.0.0/16 link-local
    if (a == 169 && b == 254) return true;

    return false;
}

std::string NetworkMonitor::TryResolveRemoteHostCached(const std::string& ip) {
    // Cache TTL: 10 minutes
    constexpr auto kTtl = std::chrono::minutes(10);
    const auto now = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(rdns_mutex_);
        auto it = rdns_cache_.find(ip);
        if (it != rdns_cache_.end()) {
            if ((now - it->second.second) < kTtl) {
                return it->second.first;
            }
            rdns_cache_.erase(it);
        }
    }

    // Best-effort reverse DNS. This can block in some environments, so we keep it conservative:
    // - only attempt for public IPv4
    // - short-circuit if parsing fails
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
        return "";
    }

    char host[NI_MAXHOST] = {0};
    int rc = getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (rc != 0) {
        // Cache negative result briefly to avoid repeated lookups.
        std::lock_guard<std::mutex> lock(rdns_mutex_);
        rdns_cache_[ip] = {"", now};
        return "";
    }

    std::string resolved = ToLowerAscii(std::string(host));
    {
        std::lock_guard<std::mutex> lock(rdns_mutex_);
        rdns_cache_[ip] = {resolved, now};
    }
    return resolved;
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
