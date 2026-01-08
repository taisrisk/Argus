#include "file_monitor.h"
#include <windows.h>
#include <algorithm>

namespace argus {

FileMonitor::FileMonitor() 
    : is_active_(false) {
}

FileMonitor::~FileMonitor() {
    if (is_active_) {
        Shutdown();
    }
}

bool FileMonitor::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    last_check_ = std::chrono::system_clock::now();
    
    return true;
}

void FileMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    events_.clear();
    browser_data_paths_.clear();
    browser_pids_.clear();
}

void FileMonitor::SetBrowserDataPaths(const std::vector<std::string>& paths) {
    browser_data_paths_ = paths;
}

void FileMonitor::SetBrowserProcessIds(const std::vector<uint32_t>& pids) {
    browser_pids_ = pids;
}

void FileMonitor::Update() {
    if (!is_active_) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_check_).count();
    
    if (elapsed >= 15) {
        MonitorDataPaths();
        last_check_ = now;
    }
}

std::vector<FileAccessEvent> FileMonitor::GetRecentEvents(int max_count) {
    if (events_.size() <= static_cast<size_t>(max_count)) {
        return events_;
    }
    
    return std::vector<FileAccessEvent>(events_.end() - max_count, events_.end());
}

void FileMonitor::MonitorDataPaths() {
}

bool FileMonitor::IsExternalAccess(uint32_t pid, const std::string& path) {
    return std::find(browser_pids_.begin(), browser_pids_.end(), pid) == browser_pids_.end();
}

}
