#include "file_monitor.h"
#include <windows.h>
#include <algorithm>
#include <sys/stat.h>
#include <tlhelp32.h>

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

    // Initialize snapshots for known paths.
    for (const auto& p : browser_data_paths_) {
        SnapshotPathIfNeeded(p);
    }
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

void FileMonitor::SnapshotPathIfNeeded(const std::string& path) {
    if (snapshots_.find(path) != snapshots_.end()) {
        return;
    }

    struct _stat64 st;
    if (_stat64(path.c_str(), &st) == 0) {
        PathSnapshot snap;
        snap.last_access = st.st_atime;
        snap.last_modify = st.st_mtime;
        snap.size = st.st_size;
        snapshots_[path] = snap;
    } else {
        // Still track it so we don't keep trying every cycle.
        snapshots_[path] = PathSnapshot{0, 0, 0};
    }
}

bool FileMonitor::HasPathChanged(const std::string& path, PathSnapshot& snap) {
    struct _stat64 st;
    if (_stat64(path.c_str(), &st) != 0) {
        return false;
    }

    bool accessed = (st.st_atime != snap.last_access);
    bool modified = (st.st_mtime != snap.last_modify);
    bool size_changed = (st.st_size != snap.size);

    snap.last_access = st.st_atime;
    snap.last_modify = st.st_mtime;
    snap.size = st.st_size;

    return accessed || modified || size_changed;
}

std::vector<FileAccessEvent> FileMonitor::GetRecentEvents(int max_count) {
    if (events_.size() <= static_cast<size_t>(max_count)) {
        return events_;
    }
    
    return std::vector<FileAccessEvent>(events_.end() - max_count, events_.end());
}

void FileMonitor::MonitorDataPaths() {
    if (browser_data_paths_.empty()) {
        return;
    }

    // Heuristic polling monitor:
    // - watches a small set of high-value files (Login Data, Local State, Cookies, Web Data)
    // - if a file changes/access time updates, we attribute it to a small set of "recent" non-browser processes
    //   (this is not perfect attribution, but provides a useful signal for correlation).

    // Build a list of candidate PIDs: non-browser processes started recently.
    std::vector<uint32_t> candidate_pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                uint32_t pid = pe32.th32ProcessID;
                if (!IsExternalAccess(pid, "")) {
                    continue;
                }

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!hProcess) {
                    continue;
                }

                FILETIME createTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                    ULARGE_INTEGER create;
                    create.LowPart = createTime.dwLowDateTime;
                    create.HighPart = createTime.dwHighDateTime;

                    FILETIME nowFT;
                    GetSystemTimeAsFileTime(&nowFT);
                    ULARGE_INTEGER now;
                    now.LowPart = nowFT.dwLowDateTime;
                    now.HighPart = nowFT.dwHighDateTime;

                    uint64_t age_seconds = (now.QuadPart - create.QuadPart) / 10000000ULL;
                    if (age_seconds < 120) {
                        candidate_pids.push_back(pid);
                    }
                }
                CloseHandle(hProcess);
            } while (Process32NextW(snapshot, &pe32) && candidate_pids.size() < 15);
        }
        CloseHandle(snapshot);
    }

    auto now = std::chrono::system_clock::now();

    for (const auto& path : browser_data_paths_) {
        SnapshotPathIfNeeded(path);
        auto it = snapshots_.find(path);
        if (it == snapshots_.end()) {
            continue;
        }

        if (!HasPathChanged(path, it->second)) {
            continue;
        }

        // Attribute to candidates (best-effort). Emit one event per candidate.
        for (uint32_t pid : candidate_pids) {
            FileAccessEvent evt;
            evt.timestamp = now;
            evt.process_id = pid;
            evt.process_name = "";
            evt.file_path = path;
            evt.access_type = FileAccessType::Read;
            evt.is_browser_process = false;
            evt.is_suspicious = true;
            evt.context = "Heuristic: browser data path changed/accessed; attributed to recent non-browser process";
            events_.push_back(evt);
        }

        // Cap memory.
        const size_t max_events = 500;
        if (events_.size() > max_events) {
            events_.erase(events_.begin(), events_.begin() + (events_.size() - max_events));
        }
    }
}

bool FileMonitor::IsExternalAccess(uint32_t pid, const std::string& path) {
    return std::find(browser_pids_.begin(), browser_pids_.end(), pid) == browser_pids_.end();
}

}
