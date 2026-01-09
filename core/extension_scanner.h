#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <set>
#include <windows.h>

namespace argus {

enum class RiskLevel {
    Informational,
    Low,
    Medium,
    High
};

struct ExtensionFinding {
    std::string extension_id;
    std::string extension_name;
    std::string file_path;
    std::string pattern_matched;
    RiskLevel risk_level;
    std::string explanation;
    std::chrono::system_clock::time_point timestamp;
};

struct ExtensionActivityEvent {
    std::string extension_id;
    std::string extension_name;
    std::string file_path;
    std::string change_type;
    std::chrono::system_clock::time_point timestamp;
};

struct ExtensionMonitoringProfile {
    std::string extension_id;
    std::string extension_name;
    std::string extension_path;
    std::string version;
    std::vector<std::string> permissions;
    std::vector<std::string> background_scripts;
    std::vector<std::string> content_scripts;
    RiskLevel risk_level;
    int poll_interval_ms;
    int risk_score;
    bool deep_monitoring_active;
    bool staged_files_detected;
    bool initialization_complete;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_scan;
};

class ExtensionScanner {
public:
    ExtensionScanner();
    ~ExtensionScanner();
    
    bool Initialize(bool user_consent);
    void Shutdown();
    
    void PerformInitialScan(const std::string& browser_profile_path);
    void ScanExtensionOnBrowserStart(const std::string& extension_path, const std::string& ext_id);
    void MonitorInitializationActivity(const std::string& ext_id);
    void CheckStagedFiles(const std::string& ext_id, const std::string& ext_path);
    void StartActivityMonitoring();
    void StopActivityMonitoring();
    void UpdateActivityMonitoring();
    
    void ScanExtensions(const std::string& browser_profile_path);
    std::vector<ExtensionFinding> GetFindings();
    std::vector<ExtensionActivityEvent> GetRecentActivity(int max_count = 100);
    void ClearFindings();
    
    bool HasUserConsent() const { return user_consent_; }
    bool IsInitialScanComplete() const { return initial_scan_complete_; }
    
private:
void ScanExtensionDirectory(const std::string& ext_path);
void AnalyzeManifest(const std::string& manifest_path, const std::string& ext_id);
ExtensionMonitoringProfile ParseManifest(const std::string& manifest_path, const std::string& ext_id);
int CalculateRiskScore(const ExtensionMonitoringProfile& profile);
RiskLevel AssessPermissions(const std::vector<std::string>& permissions);
    
    void MonitorExtensionActivity(const ExtensionMonitoringProfile& profile);
    void StartWatchersForProfile(const ExtensionMonitoringProfile& profile);
    void StopWatchersForProfile(const std::string& extension_id);
    static DWORD WINAPI ExtensionWatcherThread(LPVOID param);
    
    bool is_active_;
    bool user_consent_;
    bool initial_scan_complete_;
    bool activity_monitoring_active_;
    std::vector<ExtensionFinding> findings_;
    std::vector<ExtensionActivityEvent> activity_events_;
    std::map<std::string, ExtensionMonitoringProfile> monitored_extensions_;
    std::map<std::string, HANDLE> extension_watcher_threads_;
    std::set<std::string> watched_extension_paths_;
};

}
