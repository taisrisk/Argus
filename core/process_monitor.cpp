#include "process_monitor.h"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>

namespace argus {

ProcessMonitor::ProcessMonitor() 
    : is_active_(false), is_browser_active_(false) {
}

ProcessMonitor::~ProcessMonitor() {
    if (is_active_) {
        Shutdown();
    }
}

bool ProcessMonitor::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    last_update_ = std::chrono::system_clock::now();
    ScanForBrowserProcesses();
    
    return true;
}

void ProcessMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    events_.clear();
    tracked_pids_.clear();
}

void ProcessMonitor::Update() {
    if (!is_active_) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_update_).count();
    
    if (elapsed >= 5) {
        ScanForBrowserProcesses();
        UpdateProcessStates();
        last_update_ = now;
    }
}

std::vector<ProcessEvent> ProcessMonitor::GetRecentEvents(int max_count) {
    if (events_.size() <= static_cast<size_t>(max_count)) {
        return events_;
    }
    
    return std::vector<ProcessEvent>(events_.end() - max_count, events_.end());
}

void ProcessMonitor::ScanForBrowserProcesses() {
    std::vector<std::string> browser_names = {
        "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe"
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    std::vector<uint32_t> current_pids;
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            wchar_t* wExeName = pe32.szExeFile;
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, wExeName, -1, nullptr, 0, nullptr, nullptr);
            std::string proc_name(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, wExeName, -1, &proc_name[0], size_needed, nullptr, nullptr);
            
            if (proc_name.back() == '\0') {
                proc_name.pop_back();
            }
            
            std::transform(proc_name.begin(), proc_name.end(), proc_name.begin(), ::tolower);
            
            for (const auto& browser : browser_names) {
                if (proc_name == browser) {
                    current_pids.push_back(pe32.th32ProcessID);
                    
                    if (std::find(tracked_pids_.begin(), tracked_pids_.end(), pe32.th32ProcessID) == tracked_pids_.end()) {
                        ProcessEvent event;
                        event.timestamp = std::chrono::system_clock::now();
                        event.process_id = pe32.th32ProcessID;
                        
                        size_needed = WideCharToMultiByte(CP_UTF8, 0, wExeName, -1, nullptr, 0, nullptr, nullptr);
                        event.process_name.resize(size_needed);
                        WideCharToMultiByte(CP_UTF8, 0, wExeName, -1, &event.process_name[0], size_needed, nullptr, nullptr);
                        if (event.process_name.back() == '\0') {
                            event.process_name.pop_back();
                        }
                        
                        event.state = ProcessState::Running;
                        event.context = "Browser process started";
                        events_.push_back(event);
                    }
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    
    for (uint32_t old_pid : tracked_pids_) {
        if (std::find(current_pids.begin(), current_pids.end(), old_pid) == current_pids.end()) {
            ProcessEvent event;
            event.timestamp = std::chrono::system_clock::now();
            event.process_id = old_pid;
            event.state = ProcessState::Unknown;
            event.context = "Browser process stopped";
            events_.push_back(event);
        }
    }
    
    tracked_pids_ = current_pids;
    is_browser_active_ = !tracked_pids_.empty();
    
    CloseHandle(snapshot);
}

void ProcessMonitor::UpdateProcessStates() {
    HWND foreground = GetForegroundWindow();
    DWORD foreground_pid = 0;
    
    if (foreground) {
        GetWindowThreadProcessId(foreground, &foreground_pid);
    }
    
    for (uint32_t pid : tracked_pids_) {
        ProcessState state = (pid == foreground_pid) ? ProcessState::Focused : ProcessState::Background;
        
        if (!events_.empty() && events_.back().process_id == pid && events_.back().state != state) {
            ProcessEvent event;
            event.timestamp = std::chrono::system_clock::now();
            event.process_id = pid;
            event.state = state;
            event.context = (state == ProcessState::Focused) ? "Browser focused" : "Browser in background";
            events_.push_back(event);
        }
    }
}

}
