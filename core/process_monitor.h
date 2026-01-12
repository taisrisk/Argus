#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace argus {

enum class ProcessState {
    Unknown,
    Running,
    Idle,
    Focused,
    Background
};

struct ProcessEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t process_id;
    std::string process_name;
    ProcessState state;
    std::string context;
};

struct ProcessStartInfo {
    uint32_t pid = 0;
    std::string image_path;
};

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    
    bool Initialize();
    void Shutdown();
    
    void Update();
    std::vector<ProcessEvent> GetRecentEvents(int max_count = 100);
    std::vector<uint32_t> GetBrowserPids() const { return tracked_pids_; }

    // Returns processes that started since the last scan.
    std::vector<ProcessStartInfo> ConsumeNewProcesses();
    
    bool IsBrowserActive() const { return is_browser_active_; }
    
private:
    void ScanForBrowserProcesses();
    void UpdateProcessStates();
    void ScanForNewProcesses();
    
    bool is_active_;
    bool is_browser_active_;
    std::vector<ProcessEvent> events_;
    std::vector<uint32_t> tracked_pids_;
    std::vector<ProcessStartInfo> new_processes_;
    std::vector<uint32_t> last_seen_pids_;
    std::chrono::system_clock::time_point last_update_;
};

}
