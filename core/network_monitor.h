#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <set>
#include <unordered_map>
#include <mutex>

namespace argus {

enum class ConnectionType {
    Unknown,
    TCP,
    UDP
};

struct NetworkEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t process_id;
    std::string remote_address;
    uint16_t remote_port;
    ConnectionType type;
    std::string context;
    bool is_suspicious;
};

class NetworkMonitor {
public:
    NetworkMonitor();
    ~NetworkMonitor();
    
    bool Initialize();
    void Shutdown();
    
    void Update();
    std::vector<NetworkEvent> GetRecentEvents(int max_count = 100);
    
    void SetTrackedProcesses(const std::vector<uint32_t>& pids);
    
private:
    void ScanConnections();
    bool IsWhitelisted(const std::string& address);
    bool IsBlacklisted(const std::string& address);
    bool IsSuspiciousPattern(const NetworkEvent& event);

    // Best-effort reverse DNS (cached). Never blocks the hot path.
    std::string TryResolveRemoteHostCached(const std::string& ip);
    static bool IsPrivateOrLoopbackIPv4(const std::string& ip);
    
    bool is_active_;
    std::vector<NetworkEvent> events_;
    std::vector<uint32_t> tracked_pids_;
    std::set<std::string> whitelist_;
    std::set<std::string> blacklist_;
    std::chrono::system_clock::time_point last_scan_;

    std::unordered_map<std::string, std::pair<std::string, std::chrono::steady_clock::time_point>> rdns_cache_;
    std::mutex rdns_mutex_;
};

}
