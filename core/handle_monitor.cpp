#include "handle_monitor.h"
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>

namespace argus {

HandleMonitor::HandleMonitor() : is_active_(false) {
}

HandleMonitor::~HandleMonitor() {
    if (is_active_) {
        Shutdown();
    }
}

bool HandleMonitor::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    last_cleanup_ = std::chrono::system_clock::now();
    
    std::cout << "[HandleMonitor] Cross-process handle tracking active" << std::endl;
    
    return true;
}

void HandleMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    activities_.clear();
    browser_pids_.clear();
}

void HandleMonitor::SetBrowserProcessIds(const std::vector<uint32_t>& pids) {
    browser_pids_ = pids;
}

bool HandleMonitor::IsBrowserProcess(uint32_t pid) {
    return std::find(browser_pids_.begin(), browser_pids_.end(), pid) != browser_pids_.end();
}

std::string HandleMonitor::GetProcessPath(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return "Unknown";
    }
    
    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return std::string(path);
    }
    
    CloseHandle(hProcess);
    return "Unknown";
}

int HandleMonitor::ScoreAccessRights(DWORD access_mask) {
    int score = 0;
    
    // Dangerous rights
    if (access_mask & PROCESS_VM_READ) score += 10;
    if (access_mask & PROCESS_VM_WRITE) score += 20;
    if (access_mask & PROCESS_VM_OPERATION) score += 15;
    if (access_mask & PROCESS_CREATE_THREAD) score += 25;
    if (access_mask & PROCESS_DUP_HANDLE) score += 15;
    if (access_mask & PROCESS_QUERY_INFORMATION) score += 3;
    if (access_mask & PROCESS_QUERY_LIMITED_INFORMATION) score += 2;
    if (access_mask & PROCESS_ALL_ACCESS) score += 50;
    
    return score;
}

void HandleMonitor::RecordHandleOpen(uint32_t source_pid, uint32_t target_pid, HANDLE handle, DWORD access) {
    if (!is_active_) return;
    
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    // Initialize activity if not exists
    if (activities_.find(source_pid) == activities_.end()) {
        ProcessHandleActivity activity;
        activity.pid = source_pid;
        activity.process_path = GetProcessPath(source_pid);
        activity.first_seen = now;
        activity.last_activity = now;
        activity.suspicious_handle_count = 0;
        activity.memory_read_count = 0;
        activity.risk_score = 0;
        activity.targets_browser = false;
        activity.has_dpapi_access = false;
        activity.has_sqlite_staging = false;
        activities_[source_pid] = activity;
    }
    
    // Create handle event
    HandleEvent event;
    event.timestamp = now;
    event.source_pid = source_pid;
    event.target_pid = target_pid;
    event.handle_value = handle;
    event.desired_access = access;
    event.source_process_path = activities_[source_pid].process_path;
    event.target_process_path = GetProcessPath(target_pid);
    event.risk_score = ScoreAccessRights(access);
    event.is_suspicious = event.risk_score >= 15;
    
    // Check if targeting browser
    if (IsBrowserProcess(target_pid)) {
        event.risk_score += 20;
        event.is_suspicious = true;
        activities_[source_pid].targets_browser = true;
    }
    
    activities_[source_pid].handle_opens.push_back(event);
    activities_[source_pid].last_activity = now;
    
    if (event.is_suspicious) {
        activities_[source_pid].suspicious_handle_count++;
    }
    
    activities_[source_pid].risk_score = CalculateHandleRiskScore(source_pid);
}

void HandleMonitor::RecordMemoryRead(uint32_t caller_pid, uint32_t target_pid, HANDLE handle, PVOID address, SIZE_T size) {
    if (!is_active_) return;
    
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    // Initialize if needed
    if (activities_.find(caller_pid) == activities_.end()) {
        ProcessHandleActivity activity;
        activity.pid = caller_pid;
        activity.process_path = GetProcessPath(caller_pid);
        activity.first_seen = now;
        activity.last_activity = now;
        activity.suspicious_handle_count = 0;
        activity.memory_read_count = 0;
        activity.risk_score = 0;
        activity.targets_browser = false;
        activity.has_dpapi_access = false;
        activity.has_sqlite_staging = false;
        activities_[caller_pid] = activity;
    }
    
    // Count recent reads for frequency detection
    int recent_reads = 0;
    auto& existing_reads = activities_[caller_pid].memory_reads;
    for (auto it = existing_reads.rbegin(); it != existing_reads.rend(); ++it) {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->timestamp).count();
        if (age < 100) {
            recent_reads++;
        } else {
            break;
        }
    }
    
    // Create memory read event
    MemoryReadEvent event;
    event.timestamp = now;
    event.caller_pid = caller_pid;
    event.target_pid = target_pid;
    event.process_handle = handle;
    event.base_address = address;
    event.size = size;
    event.frequency_count = recent_reads + 1;
    event.caller_path = activities_[caller_pid].process_path;
    event.target_path = GetProcessPath(target_pid);
    event.risk_score = 3; // Base score
    
    // Risk scoring
    if (IsBrowserProcess(target_pid)) {
        event.risk_score += 8; // Reading browser memory
        activities_[caller_pid].targets_browser = true;
    }
    
    if (recent_reads > 0) {
        event.risk_score += 5; // Repeated reads within 100ms
    }
    
    if (size > 10000) {
        event.risk_score += 5; // Large read
    }
    
    activities_[caller_pid].memory_reads.push_back(event);
    activities_[caller_pid].memory_read_count++;
    activities_[caller_pid].last_activity = now;
    activities_[caller_pid].risk_score = CalculateHandleRiskScore(caller_pid);
}

bool HandleMonitor::IsHandleAccessSuspicious(DWORD access_mask, uint32_t target_pid) {
    int score = ScoreAccessRights(access_mask);
    
    if (IsBrowserProcess(target_pid)) {
        score += 20;
    }
    
    return score >= 25;
}

bool HandleMonitor::IsMemoryReadPatternSuspicious(uint32_t caller_pid, uint32_t target_pid) {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    auto it = activities_.find(caller_pid);
    if (it == activities_.end()) {
        return false;
    }
    
    ProcessHandleActivity& activity = it->second;
    
    // Check for rapid reads
    if (activity.memory_read_count > 3 && activity.targets_browser) {
        return true;
    }
    
    // Check for suspicious handle + memory read combo
    if (activity.suspicious_handle_count > 0 && activity.memory_read_count > 0) {
        return true;
    }
    
    return false;
}

int HandleMonitor::CalculateHandleRiskScore(uint32_t pid) {
    auto it = activities_.find(pid);
    if (it == activities_.end()) {
        return 0;
    }
    
    ProcessHandleActivity& activity = it->second;
    int score = 0;
    
    // Suspicious handles
    score += activity.suspicious_handle_count * 10;
    
    // Memory reads
    score += activity.memory_read_count * 5;
    
    // Targets browser
    if (activity.targets_browser) {
        score += 15;
    }
    
    // Rapid activity
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        activity.last_activity - activity.first_seen).count();
    
    if (duration < 10 && (activity.suspicious_handle_count > 0 || activity.memory_read_count > 0)) {
        score += 10;
    }
    
    // High-frequency reads
    int recent_reads = 0;
    auto now = std::chrono::system_clock::now();
    for (auto& read : activity.memory_reads) {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - read.timestamp).count();
        if (age < 1000) {
            recent_reads++;
        }
    }
    
    if (recent_reads > 5) {
        score += 20;
    }
    
    return score;
}

ProcessHandleActivity* HandleMonitor::GetProcessActivity(uint32_t pid) {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    auto it = activities_.find(pid);
    if (it != activities_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<ProcessHandleActivity> HandleMonitor::GetHighRiskActivities(int min_score) {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    std::vector<ProcessHandleActivity> high_risk;
    
    for (auto& pair : activities_) {
        if (pair.second.risk_score >= min_score) {
            high_risk.push_back(pair.second);
        }
    }
    
    return high_risk;
}

std::vector<MemoryReadEvent> HandleMonitor::GetRecentMemoryReads(uint32_t pid, int max_count) {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    auto it = activities_.find(pid);
    if (it == activities_.end()) {
        return std::vector<MemoryReadEvent>();
    }
    
    auto& reads = it->second.memory_reads;
    
    if (reads.size() <= static_cast<size_t>(max_count)) {
        return reads;
    }
    
    return std::vector<MemoryReadEvent>(reads.end() - max_count, reads.end());
}

void HandleMonitor::CleanupOldActivities(int max_age_seconds) {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    std::vector<uint32_t> expired_pids;
    for (auto& pair : activities_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.last_activity).count();
        if (age > max_age_seconds) {
            expired_pids.push_back(pair.first);
        }
    }
    
    for (uint32_t pid : expired_pids) {
        activities_.erase(pid);
    }
}

}
