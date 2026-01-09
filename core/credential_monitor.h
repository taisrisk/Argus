#pragma once

#include "file_identity.h"
#include "file_neutralizer.h"
#include "prevention_logger.h"
#include "process_whitelist.h"
#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <set>
#include <cstdint>
#include <thread>
#include <atomic>
#include <mutex>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

namespace argus {

enum class AssetType {
    Cookies,
    LoginData,
    LocalState,
    WebData,
    ExtensionScript,
    Unknown
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

struct ProcessFingerprint {
    std::string sha256_hash;
    std::string compile_time;
    bool has_signature;
    std::string signature_info;
    std::vector<std::string> staged_files;
    int forensic_score;
    
    // Enhanced forensic data
    std::string pe_timestamp;
    std::string pe_subsystem;
    uint32_t pe_characteristics;
    std::vector<std::string> import_dlls;
    size_t memory_working_set;
    std::string parent_process_path;
    uint32_t parent_pid;
    bool is_packed;
    std::string process_user;
    std::vector<std::string> open_handles;
    std::chrono::system_clock::time_point creation_time;
    int64_t process_age_ms;
};

enum class ThreatAction {
    Monitor,
    Suspend,
    Terminate,
    Whitelist
};

struct ThreatChain {
    uint32_t pid;
    std::string process_path;
    std::vector<AccessEvent> events;
    int risk_score;
    std::chrono::system_clock::time_point first_event;
    std::chrono::system_clock::time_point last_event;
    bool reported;
    bool is_suspended;
    ThreatAction action;
    ProcessFingerprint fingerprint;
};

struct FileSnapshot {
    std::string path;
    time_t last_access;
    time_t last_modify;
    int64_t size;
};

struct MonitoringStatus {
    std::string browser;
    std::string profile;
    int files_found;
    int files_monitored;
    std::vector<std::string> monitored_files;
    std::vector<std::string> missing_files;
};

class CredentialMonitor {
public:
    CredentialMonitor();
    ~CredentialMonitor();
    
    bool Initialize();
    void Shutdown();
    
    void RegisterBrowserProfile(const std::string& browser, const std::string& profile_path);
    MonitoringStatus RegisterBrowserProfileWithStatus(const std::string& browser, const std::string& profile_path);
    void SetBrowserProcessIds(const std::vector<uint32_t>& pids);
    
    void Update();
    std::vector<ThreatChain> GetActiveThreats();
    
    void TerminateThread(uint32_t pid);
    bool SuspendProcess(uint32_t pid);
    bool ResumeProcess(uint32_t pid);
    ProcessFingerprint ExtractFingerprint(uint32_t pid);
    ThreatAction DecideThreatAction(const ThreatChain& chain);
    bool KillProcess(uint32_t pid);
    
    void OnFileAccess(uint32_t pid, const std::wstring& filepath);
    
    bool IsTrustedBrowserService(const std::string& process_path);
    bool IsCriticalBrowserComponent(const std::string& process_path);
    std::string ClassifyProcessType(uint32_t pid, const std::string& process_path);
    
    void StartDirectoryWatchers();
    void StopDirectoryWatchers();
    bool AreWatchersRunning() const { return !watcher_threads_.empty(); }
    static DWORD WINAPI WatcherThread(LPVOID param);
    static DWORD WINAPI PollingThread(LPVOID param);
    static DWORD WINAPI TempFileWatcherThread(LPVOID param);
    
private:
    void StartETWSession();
    void StopETWSession();
    static void WINAPI ETWCallback(PEVENT_RECORD eventRecord);
    
    void CheckFileChanges();
    std::vector<uint32_t> FindProcessesWithFileOpen(const std::string& filepath);
    std::vector<uint32_t> GetRecentProcesses();
    
    bool IsSensitiveFile(const std::wstring& filepath);
    AssetType GetAssetType(const std::wstring& filepath);
    void RecordAccess(uint32_t pid, const std::wstring& filepath);
    std::string GetProcessPath(uint32_t pid);
    bool IsProcessSuspicious(uint32_t pid);
    void AnalyzeAccessPatterns();
    int CalculateRiskScore(const ThreatChain& chain);
    
    bool is_active_;
    std::vector<SensitiveAsset> asset_registry_;
    std::vector<uint32_t> browser_pids_;
    std::map<uint32_t, ThreatChain> active_chains_;
    std::chrono::system_clock::time_point last_check_;
    std::map<std::string, std::string> profile_paths_;
    std::map<std::string, FileSnapshot> file_snapshots_;
    std::vector<std::string> watched_directories_;
    std::vector<HANDLE> watcher_threads_;
    HANDLE polling_thread_;
    HANDLE temp_watcher_thread_;
    
    FileIdentityTracker file_identity_tracker_;
    ProcessWhitelist process_whitelist_;
    
    TRACEHANDLE session_handle_;
    TRACEHANDLE trace_handle_;
    std::thread etw_thread_;
    std::atomic<bool> etw_running_;
    std::mutex chains_mutex_;
    
    static CredentialMonitor* s_instance;
    
    friend class ThreatDetector;
    friend class MonitoringThreads;
};

}



