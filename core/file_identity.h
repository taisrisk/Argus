#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <chrono>

namespace argus {

struct FileIdentity {
    uint64_t file_id;
    uint32_t volume_serial;
    std::string canonical_path;
    std::string browser;
    std::string profile;
    std::string logical_type;
};

struct FileAccessContext {
    std::chrono::system_clock::time_point timestamp;
    uint32_t pid;
    std::string process_path;
    std::string accessed_path;
    uint64_t file_id;
    bool is_reparse_point;
    bool is_indirect_access;
};

struct ProcessActivity {
    uint32_t pid;
    std::string process_path;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_activity;
    
    std::vector<FileAccessContext> file_accesses;
    std::vector<std::string> file_writes;
    std::vector<std::string> temp_db_files;
    std::vector<std::string> network_connections;
    
    bool has_code_signature;
    std::string parent_process;
    int behavior_score;
    bool has_temp_staging;
};

class FileIdentityTracker {
public:
    FileIdentityTracker();
    ~FileIdentityTracker();
    
    bool Initialize();
    void Shutdown();
    
    bool RegisterFile(const std::string& path, const std::string& browser, 
                     const std::string& profile, const std::string& logical_type);
    
    bool IsMonitoredFile(uint64_t file_id, uint32_t volume_serial);
    FileIdentity* GetFileIdentity(uint64_t file_id, uint32_t volume_serial);
    
    bool GetFileIdentity(const std::string& path, uint64_t& file_id, uint32_t& volume_serial);
    bool IsReparsePoint(const std::string& path);
    std::string ResolveReparseTarget(const std::string& path);
    
    void RecordFileAccess(uint32_t pid, const std::string& accessed_path, 
                         uint64_t file_id, uint32_t volume_serial, bool is_indirect);
    
    void RecordFileWrite(uint32_t pid, const std::string& written_path);
    void RecordNetworkActivity(uint32_t pid, const std::string& remote_address);
    
    ProcessActivity* GetProcessActivity(uint32_t pid);
    int CalculateBehaviorScore(uint32_t pid);
    
    std::vector<ProcessActivity> GetHighRiskActivities(int min_score = 90);
    
private:
    bool is_active_;
    std::map<std::pair<uint64_t, uint32_t>, FileIdentity> file_registry_;
    std::map<uint32_t, ProcessActivity> process_activities_;
    std::chrono::system_clock::time_point last_cleanup_;
};

}
