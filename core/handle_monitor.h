#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <mutex>

namespace argus {

struct HandleEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t source_pid;
    uint32_t target_pid;
    HANDLE handle_value;
    DWORD desired_access;
    std::string source_process_path;
    std::string target_process_path;
    bool is_suspicious;
    int risk_score;
};

struct MemoryReadEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t caller_pid;
    uint32_t target_pid;
    HANDLE process_handle;
    PVOID base_address;
    SIZE_T size;
    uint32_t frequency_count;
    std::string caller_path;
    std::string target_path;
    int risk_score;
};

struct ProcessHandleActivity {
    uint32_t pid;
    std::string process_path;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_activity;
    
    std::vector<HandleEvent> handle_opens;
    std::vector<MemoryReadEvent> memory_reads;
    
    int suspicious_handle_count;
    int memory_read_count;
    int risk_score;
    
    bool targets_browser;
    bool has_dpapi_access;
    bool has_sqlite_staging;
};

class HandleMonitor {
public:
    HandleMonitor();
    ~HandleMonitor();
    
    bool Initialize();
    void Shutdown();
    
    void SetBrowserProcessIds(const std::vector<uint32_t>& pids);
    
    // Core monitoring
    void RecordHandleOpen(uint32_t source_pid, uint32_t target_pid, HANDLE handle, DWORD access);
    void RecordMemoryRead(uint32_t caller_pid, uint32_t target_pid, HANDLE handle, PVOID address, SIZE_T size);
    
    // Analysis
    int CalculateHandleRiskScore(uint32_t pid);
    bool IsHandleAccessSuspicious(DWORD access_mask, uint32_t target_pid);
    bool IsMemoryReadPatternSuspicious(uint32_t caller_pid, uint32_t target_pid);
    
    // Queries
    ProcessHandleActivity* GetProcessActivity(uint32_t pid);
    std::vector<ProcessHandleActivity> GetHighRiskActivities(int min_score = 50);
    std::vector<MemoryReadEvent> GetRecentMemoryReads(uint32_t pid, int max_count = 10);
    
    // Cleanup
    void CleanupOldActivities(int max_age_seconds = 300);
    
private:
    bool is_active_;
    std::vector<uint32_t> browser_pids_;
    std::map<uint32_t, ProcessHandleActivity> activities_;
    std::chrono::system_clock::time_point last_cleanup_;
    std::mutex activity_mutex_;
    
    bool IsBrowserProcess(uint32_t pid);
    std::string GetProcessPath(uint32_t pid);
    int ScoreAccessRights(DWORD access_mask);
};

}
