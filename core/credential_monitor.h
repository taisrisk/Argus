#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <set>
#include <cstdint>

namespace argus {

enum class AssetType {
    Cookies,
    LoginData,
    LocalState,
    WebData,
    ExtensionScript
};

struct SensitiveAsset {
    std::string browser;
    std::string profile;
    std::string file_path;
    AssetType type;
    bool is_decoy;
};

struct AccessEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t pid;
    uint32_t parent_pid;
    std::string process_path;
    std::string file_accessed;
    AssetType asset_type;
    bool is_browser_process;
    bool is_decoy_hit;
};

struct ThreatChain {
    uint32_t pid;
    std::string process_path;
    std::vector<AccessEvent> events;
    int risk_score;
    std::chrono::system_clock::time_point first_event;
    std::chrono::system_clock::time_point last_event;
};

class CredentialMonitor {
public:
    CredentialMonitor();
    ~CredentialMonitor();
    
    bool Initialize();
    void Shutdown();
    
    void RegisterBrowserProfile(const std::string& browser, const std::string& profile_path);
    void SetBrowserProcessIds(const std::vector<uint32_t>& pids);
    
    void Update();
    std::vector<ThreatChain> GetActiveThreats();
    
private:
    void BuildAssetRegistry();
    void CreateDecoyProfile(const std::string& browser, const std::string& base_path);
    void MonitorFileAccess();
    void AnalyzeAccessPatterns();
    int CalculateRiskScore(const ThreatChain& chain);
    bool IsProcessSuspicious(uint32_t pid);
    
    bool is_active_;
    std::vector<SensitiveAsset> asset_registry_;
    std::vector<uint32_t> browser_pids_;
    std::map<uint32_t, ThreatChain> active_chains_;
    std::chrono::system_clock::time_point last_check_;
};

}
