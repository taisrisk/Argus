#pragma once

#include "file_identity.h"
#include "file_neutralizer.h"
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

struct ThreatChain {
    uint32_t pid;
    std::string process_path;
    std::vector<AccessEvent> events;
    int risk_score;
    std::chrono::system_clock::time_point first_event;
    std::chrono::system_clock::time_point last_event;
    bool reported;
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
    bool KillProcess(uint32_t pid);
    
    void OnFileAccess(uint32_t pid, const std::wstring& filepath);
    
    void StartDirectoryWatchers();
    void StopDirectoryWatchers();
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
    
    TRACEHANDLE session_handle_;
    TRACEHANDLE trace_handle_;
    std::thread etw_thread_;
    std::atomic<bool> etw_running_;
    std::mutex chains_mutex_;
    
    static CredentialMonitor* s_instance;
};

}



