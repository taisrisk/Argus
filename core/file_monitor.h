#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace argus {

enum class FileAccessType {
    Read,
    Write,
    Delete,
    Unknown
};

struct FileAccessEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t process_id;
    std::string process_name;
    std::string file_path;
    FileAccessType access_type;
    bool is_browser_process;
    bool is_suspicious;
    std::string context;
};

class FileMonitor {
public:
    FileMonitor();
    ~FileMonitor();
    
    bool Initialize();
    void Shutdown();
    
    void SetBrowserDataPaths(const std::vector<std::string>& paths);
    void SetBrowserProcessIds(const std::vector<uint32_t>& pids);
    
    void Update();
    std::vector<FileAccessEvent> GetRecentEvents(int max_count = 100);
    
private:
    void MonitorDataPaths();
    bool IsExternalAccess(uint32_t pid, const std::string& path);
    
    bool is_active_;
    std::vector<std::string> browser_data_paths_;
    std::vector<uint32_t> browser_pids_;
    std::vector<FileAccessEvent> events_;
    std::chrono::system_clock::time_point last_check_;
};

}
