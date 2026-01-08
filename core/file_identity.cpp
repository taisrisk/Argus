#include "file_identity.h"
#include <iostream>
#include <algorithm>
#include <set>

namespace argus {

FileIdentityTracker::FileIdentityTracker() : is_active_(false) {
}

FileIdentityTracker::~FileIdentityTracker() {
    if (is_active_) {
        Shutdown();
    }
}

bool FileIdentityTracker::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    last_cleanup_ = std::chrono::system_clock::now();
    
    std::cout << "[FileIdentityTracker] Identity-based monitoring active" << std::endl;
    
    return true;
}

void FileIdentityTracker::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    file_registry_.clear();
    process_activities_.clear();
}

bool FileIdentityTracker::RegisterFile(const std::string& path, const std::string& browser, 
                                       const std::string& profile, const std::string& logical_type) {
    uint64_t file_id;
    uint32_t volume_serial;
    
    if (!GetFileIdentity(path, file_id, volume_serial)) {
        return false;
    }
    
    FileIdentity identity;
    identity.file_id = file_id;
    identity.volume_serial = volume_serial;
    identity.canonical_path = path;
    identity.browser = browser;
    identity.profile = profile;
    identity.logical_type = logical_type;
    
    auto key = std::make_pair(file_id, volume_serial);
    file_registry_[key] = identity;
    
    return true;
}

bool FileIdentityTracker::GetFileIdentity(const std::string& path, uint64_t& file_id, uint32_t& volume_serial) {
    HANDLE hFile = CreateFileA(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        CloseHandle(hFile);
        return false;
    }
    
    volume_serial = fileInfo.dwVolumeSerialNumber;
    file_id = ((uint64_t)fileInfo.nFileIndexHigh << 32) | fileInfo.nFileIndexLow;
    
    CloseHandle(hFile);
    return true;
}

bool FileIdentityTracker::IsMonitoredFile(uint64_t file_id, uint32_t volume_serial) {
    auto key = std::make_pair(file_id, volume_serial);
    return file_registry_.find(key) != file_registry_.end();
}

FileIdentity* FileIdentityTracker::GetFileIdentity(uint64_t file_id, uint32_t volume_serial) {
    auto key = std::make_pair(file_id, volume_serial);
    auto it = file_registry_.find(key);
    if (it != file_registry_.end()) {
        return &it->second;
    }
    return nullptr;
}

bool FileIdentityTracker::IsReparsePoint(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

std::string FileIdentityTracker::ResolveReparseTarget(const std::string& path) {
    HANDLE hFile = CreateFileA(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }
    
    char buffer[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(hFile, buffer, MAX_PATH, FILE_NAME_NORMALIZED);
    
    CloseHandle(hFile);
    
    if (result > 0 && result < MAX_PATH) {
        return std::string(buffer);
    }
    
    return "";
}

void FileIdentityTracker::RecordFileAccess(uint32_t pid, const std::string& accessed_path, 
                                           uint64_t file_id, uint32_t volume_serial, bool is_indirect) {
    auto now = std::chrono::system_clock::now();
    
    if (process_activities_.find(pid) == process_activities_.end()) {
        ProcessActivity activity;
        activity.pid = pid;
        activity.first_seen = now;
        activity.last_activity = now;
        activity.behavior_score = 0;
        activity.has_code_signature = false;
        activity.has_temp_staging = false;
        process_activities_[pid] = activity;
    }
    
    FileAccessContext context;
    context.timestamp = now;
    context.pid = pid;
    context.accessed_path = accessed_path;
    context.file_id = file_id;
    context.is_reparse_point = IsReparsePoint(accessed_path);
    context.is_indirect_access = is_indirect;
    
    process_activities_[pid].file_accesses.push_back(context);
    process_activities_[pid].last_activity = now;
    process_activities_[pid].behavior_score = CalculateBehaviorScore(pid);
}

void FileIdentityTracker::RecordFileWrite(uint32_t pid, const std::string& written_path) {
    auto now = std::chrono::system_clock::now();
    
    if (process_activities_.find(pid) == process_activities_.end()) {
        ProcessActivity activity;
        activity.pid = pid;
        activity.first_seen = now;
        activity.last_activity = now;
        activity.behavior_score = 0;
        activity.has_code_signature = false;
        activity.has_temp_staging = false;
        process_activities_[pid] = activity;
    }
    
    std::string lower = written_path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    bool is_temp_db = (lower.find("temp.db") != std::string::npos ||
                       lower.find("tempcookies") != std::string::npos ||
                       lower.find("temp_cookies") != std::string::npos ||
                       lower.find("temp_login") != std::string::npos ||
                       lower.find("temp_pass") != std::string::npos ||
                       lower.find("staging") != std::string::npos ||
                       lower.find("dump") != std::string::npos ||
                       (lower.find(".db") != std::string::npos && lower.find("\\temp\\") != std::string::npos) ||
                       (lower.find(".sqlite") != std::string::npos && lower.find("\\temp\\") != std::string::npos));
    
    process_activities_[pid].file_writes.push_back(written_path);
    
    if (is_temp_db) {
        process_activities_[pid].temp_db_files.push_back(written_path);
        process_activities_[pid].has_temp_staging = true;
    }
    
    process_activities_[pid].last_activity = now;
    process_activities_[pid].behavior_score = CalculateBehaviorScore(pid);
}

void FileIdentityTracker::RecordNetworkActivity(uint32_t pid, const std::string& remote_address) {
    auto now = std::chrono::system_clock::now();
    
    if (process_activities_.find(pid) == process_activities_.end()) {
        ProcessActivity activity;
        activity.pid = pid;
        activity.first_seen = now;
        activity.last_activity = now;
        activity.behavior_score = 0;
        activity.has_code_signature = false;
        activity.has_temp_staging = false;
        process_activities_[pid] = activity;
    }
    
    process_activities_[pid].network_connections.push_back(remote_address);
    process_activities_[pid].last_activity = now;
    process_activities_[pid].behavior_score = CalculateBehaviorScore(pid);
}

ProcessActivity* FileIdentityTracker::GetProcessActivity(uint32_t pid) {
    auto it = process_activities_.find(pid);
    if (it != process_activities_.end()) {
        return &it->second;
    }
    return nullptr;
}

int FileIdentityTracker::CalculateBehaviorScore(uint32_t pid) {
    auto it = process_activities_.find(pid);
    if (it == process_activities_.end()) {
        return 0;
    }
    
    ProcessActivity& activity = it->second;
    int score = 0;
    
    score += 20;
    
    int unique_files = 0;
    std::set<uint64_t> seen_files;
    for (const auto& access : activity.file_accesses) {
        if (seen_files.insert(access.file_id).second) {
            unique_files++;
        }
    }
    score += unique_files * 30;
    
    for (const auto& access : activity.file_accesses) {
        if (access.is_indirect_access || access.is_reparse_point) {
            score += 25;
        }
    }
    
    if (unique_files >= 2) {
        score += 15;
    }
    
    if (!activity.file_writes.empty()) {
        score += 25;
    }
    
    if (activity.has_temp_staging) {
        score += 50;
    }
    
    if (!activity.temp_db_files.empty()) {
        score += 40;
    }
    
    if (!activity.network_connections.empty()) {
        score += 30;
    }
    
    if (activity.has_code_signature) {
        score -= 15;
    }
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        activity.last_activity - activity.first_seen).count();
    if (duration <= 5 && unique_files >= 2) {
        score += 20;
    }
    
    return score;
}

std::vector<ProcessActivity> FileIdentityTracker::GetHighRiskActivities(int min_score) {
    std::vector<ProcessActivity> high_risk;
    
    for (const auto& pair : process_activities_) {
        if (pair.second.behavior_score >= min_score) {
            high_risk.push_back(pair.second);
        }
    }
    
    return high_risk;
}

}
