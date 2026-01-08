#include "credential_monitor.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <set>

#pragma comment(lib, "psapi.lib")

namespace argus {

class SecurityUtils {
public:
    static bool DirectoryExists(const std::string& path) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
    }
};

CredentialMonitor* CredentialMonitor::s_instance = nullptr;

CredentialMonitor::CredentialMonitor() 
    : is_active_(false), session_handle_(0), trace_handle_(0), etw_running_(false) {
    s_instance = this;
}

CredentialMonitor::~CredentialMonitor() {
    if (is_active_) {
        Shutdown();
    }
    s_instance = nullptr;
}

bool CredentialMonitor::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    etw_running_ = true;
    last_check_ = std::chrono::system_clock::now();
    
    std::cout << "[CredentialMonitor] Real-time file monitoring active" << std::endl;
    
    return true;
}

void CredentialMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    etw_running_ = false;
    StopDirectoryWatchers();
    StopETWSession();
    
    is_active_ = false;
    asset_registry_.clear();
    browser_pids_.clear();
    active_chains_.clear();
    profile_paths_.clear();
    file_snapshots_.clear();
    watched_directories_.clear();
}

void CredentialMonitor::StartETWSession() {
}

void CredentialMonitor::StopETWSession() {
    etw_running_ = false;
    
    if (etw_thread_.joinable()) {
        etw_thread_.join();
    }
}

DWORD WINAPI CredentialMonitor::WatcherThread(LPVOID param) {
    std::string* directory = (std::string*)param;
    
    std::wstring wDirectory(directory->begin(), directory->end());
    
    HANDLE hDir = CreateFileW(
        wDirectory.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (hDir == INVALID_HANDLE_VALUE) {
        delete directory;
        return 1;
    }
    
    char buffer[4096];
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    if (!s_instance) {
        CloseHandle(hDir);
        CloseHandle(overlapped.hEvent);
        delete directory;
        return 1;
    }
    
    while (s_instance->etw_running_) {
        ResetEvent(overlapped.hEvent);
        DWORD bytesReturned = 0;
        
        BOOL result = ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            &overlapped,
            NULL
        );
        
        if (!result && GetLastError() != ERROR_IO_PENDING) {
            break;
        }
        
        DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 100);
        
        if (waitResult == WAIT_OBJECT_0) {
            if (GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE)) {
                if (bytesReturned > 0) {
                    FILE_NOTIFY_INFORMATION* info = (FILE_NOTIFY_INFORMATION*)buffer;
                    
                    do {
                        std::wstring filename(info->FileName, info->FileNameLength / sizeof(WCHAR));
                        std::wstring fullPath = wDirectory + L"\\" + filename;
                        
                        std::wstring lower = fullPath;
                        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                        
                        if (lower.find(L"login data") != std::wstring::npos ||
                            lower.find(L"cookies") != std::wstring::npos ||
                            lower.find(L"local state") != std::wstring::npos ||
                            lower.find(L"web data") != std::wstring::npos) {
                            
                            std::vector<uint32_t> recent_pids;
                            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                            if (snapshot != INVALID_HANDLE_VALUE) {
                                PROCESSENTRY32W pe32;
                                pe32.dwSize = sizeof(PROCESSENTRY32W);
                                
                                if (Process32FirstW(snapshot, &pe32)) {
                                    do {
                                        if (s_instance->IsProcessSuspicious(pe32.th32ProcessID)) {
                                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
                                            if (hProcess) {
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
                                                    if (age_seconds < 5) {
                                                        recent_pids.push_back(pe32.th32ProcessID);
                                                    }
                                                }
                                                CloseHandle(hProcess);
                                            }
                                        }
                                    } while (Process32NextW(snapshot, &pe32) && recent_pids.size() < 3);
                                }
                                CloseHandle(snapshot);
                            }
                            
                            if (!recent_pids.empty()) {
                                for (uint32_t pid : recent_pids) {
                                    std::lock_guard<std::mutex> lock(s_instance->chains_mutex_);
                                    s_instance->RecordAccess(pid, fullPath);
                                }
                            }
                        }
                        
                        if (info->NextEntryOffset == 0) break;
                        info = (FILE_NOTIFY_INFORMATION*)((BYTE*)info + info->NextEntryOffset);
                    } while (true);
                }
            }
        } else if (waitResult == WAIT_TIMEOUT) {
            continue;
        } else {
            break;
        }
    }
    
    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
    delete directory;
    return 0;
}

void CredentialMonitor::StartDirectoryWatchers() {
    std::set<std::string> unique_dirs;
    
    for (const auto& asset : asset_registry_) {
        size_t lastSlash = asset.file_path.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            std::string dir = asset.file_path.substr(0, lastSlash);
            unique_dirs.insert(dir);
        }
    }
    
    for (const auto& dir : unique_dirs) {
        if (SecurityUtils::DirectoryExists(dir)) {
            std::string* dirCopy = new std::string(dir);
            watched_directories_.push_back(dir);
            HANDLE hThread = CreateThread(NULL, 0, WatcherThread, dirCopy, 0, NULL);
            if (hThread) {
                watcher_threads_.push_back(hThread);
            }
        }
    }
    
    if (!watcher_threads_.empty()) {
        std::cout << "[CredentialMonitor] Started " << watcher_threads_.size() << " directory watchers" << std::endl;
    }
}

void CredentialMonitor::StopDirectoryWatchers() {
    for (HANDLE hThread : watcher_threads_) {
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);
    }
    watcher_threads_.clear();
    watched_directories_.clear();
}

void WINAPI CredentialMonitor::ETWCallback(PEVENT_RECORD eventRecord) {
}

void CredentialMonitor::OnFileAccess(uint32_t pid, const std::wstring& filepath) {
    if (IsSensitiveFile(filepath) && IsProcessSuspicious(pid)) {
        std::lock_guard<std::mutex> lock(chains_mutex_);
        RecordAccess(pid, filepath);
    }
}

void CredentialMonitor::RegisterBrowserProfile(const std::string& browser, const std::string& profile_path) {
    RegisterBrowserProfileWithStatus(browser, profile_path);
}

MonitoringStatus CredentialMonitor::RegisterBrowserProfileWithStatus(const std::string& browser, const std::string& profile_path) {
    MonitoringStatus status;
    status.browser = browser;
    status.profile = profile_path;
    status.files_found = 0;
    status.files_monitored = 0;
    
    if (!is_active_) {
        return status;
    }
    
    profile_paths_[browser] = profile_path;
    
    size_t lastSlash = profile_path.find_last_of("\\");
    std::string parent_path = (lastSlash != std::string::npos) ? profile_path.substr(0, lastSlash) : profile_path;
    
    std::vector<std::tuple<std::string, std::string, AssetType>> files = {
        {profile_path, "\\Network\\Cookies", AssetType::Cookies},
        {profile_path, "\\Login Data", AssetType::LoginData},
        {parent_path, "\\Local State", AssetType::LocalState},
        {profile_path, "\\Web Data", AssetType::WebData}
    };
    
    for (const auto& file : files) {
        std::string base_path = std::get<0>(file);
        std::string file_suffix = std::get<1>(file);
        AssetType type = std::get<2>(file);
        std::string full_path = base_path + file_suffix;
        
        SensitiveAsset asset;
        asset.browser = browser;
        asset.profile = profile_path;
        asset.file_path = full_path;
        asset.type = type;
        asset.is_decoy = false;
        asset_registry_.push_back(asset);
        
        struct _stat64 statbuf;
        if (_stat64(full_path.c_str(), &statbuf) == 0) {
            FileSnapshot snapshot;
            snapshot.path = full_path;
            snapshot.last_access = statbuf.st_atime;
            snapshot.last_modify = statbuf.st_mtime;
            snapshot.size = statbuf.st_size;
            file_snapshots_[full_path] = snapshot;
            
            status.files_found++;
            status.files_monitored++;
            
            size_t ls = full_path.find_last_of("\\");
            std::string filename = (ls != std::string::npos) ? full_path.substr(ls + 1) : full_path;
            status.monitored_files.push_back(filename);
        } else {
            size_t ls = full_path.find_last_of("\\");
            std::string filename = (ls != std::string::npos) ? full_path.substr(ls + 1) : full_path;
            status.missing_files.push_back(filename);
        }
    }
    
    return status;
}

void CredentialMonitor::SetBrowserProcessIds(const std::vector<uint32_t>& pids) {
    browser_pids_ = pids;
}

void CredentialMonitor::Update() {
    if (!is_active_) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_check_).count();
    
    if (elapsed >= 500) {
        CheckFileChanges();
        std::lock_guard<std::mutex> lock(chains_mutex_);
        AnalyzeAccessPatterns();
        last_check_ = now;
    }
}

void CredentialMonitor::CheckFileChanges() {
    for (auto& pair : file_snapshots_) {
        const std::string& path = pair.first;
        FileSnapshot& old_snap = pair.second;
        
        struct _stat64 statbuf;
        if (_stat64(path.c_str(), &statbuf) == 0) {
            bool accessed = (statbuf.st_atime != old_snap.last_access);
            bool modified = (statbuf.st_mtime != old_snap.last_modify);
            bool copied = (statbuf.st_size != old_snap.size);
            
            if (accessed || modified) {
                std::vector<uint32_t> suspicious_pids = FindProcessesWithFileOpen(path);
                
                if (suspicious_pids.empty()) {
                    suspicious_pids = GetRecentProcesses();
                }
                
                for (uint32_t pid : suspicious_pids) {
                    if (IsProcessSuspicious(pid)) {
                        std::wstring wpath(path.begin(), path.end());
                        std::lock_guard<std::mutex> lock(chains_mutex_);
                        RecordAccess(pid, wpath);
                    }
                }
            }
            
            old_snap.last_access = statbuf.st_atime;
            old_snap.last_modify = statbuf.st_mtime;
            old_snap.size = statbuf.st_size;
        }
    }
}

std::vector<uint32_t> CredentialMonitor::FindProcessesWithFileOpen(const std::string& filepath) {
    std::vector<uint32_t> pids;
    
    HANDLE hFile = CreateFileA(
        filepath.c_str(),
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_SHARING_VIOLATION) {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32W);
                
                if (Process32FirstW(snapshot, &pe32)) {
                    do {
                        if (IsProcessSuspicious(pe32.th32ProcessID)) {
                            pids.push_back(pe32.th32ProcessID);
                        }
                    } while (Process32NextW(snapshot, &pe32) && pids.size() < 5);
                }
                CloseHandle(snapshot);
            }
        }
    } else {
        CloseHandle(hFile);
    }
    
    return pids;
}

std::vector<uint32_t> CredentialMonitor::GetRecentProcesses() {
    std::vector<uint32_t> pids;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            uint32_t pid = pe32.th32ProcessID;
            if (IsProcessSuspicious(pid)) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (hProcess) {
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
                        if (age_seconds < 60) {
                            pids.push_back(pid);
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(snapshot, &pe32) && pids.size() < 10);
    }
    
    CloseHandle(snapshot);
    return pids;
}

std::vector<ThreatChain> CredentialMonitor::GetActiveThreats() {
    std::vector<ThreatChain> threats;
    
    std::lock_guard<std::mutex> lock(chains_mutex_);
    for (auto& pair : active_chains_) {
        if (pair.second.risk_score >= 5 && !pair.second.reported) {
            threats.push_back(pair.second);
            pair.second.reported = true;
        }
    }
    
    return threats;
}

bool CredentialMonitor::IsSensitiveFile(const std::wstring& filepath) {
    std::wstring lower = filepath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    if (lower.find(L"login data") != std::wstring::npos) return true;
    if (lower.find(L"cookies") != std::wstring::npos) return true;
    if (lower.find(L"local state") != std::wstring::npos) return true;
    if (lower.find(L"web data") != std::wstring::npos) return true;
    if (lower.find(L"key4.db") != std::wstring::npos) return true;
    if (lower.find(L"logins.json") != std::wstring::npos) return true;
    if (lower.find(L"cookies.sqlite") != std::wstring::npos) return true;
    
    return false;
}

AssetType CredentialMonitor::GetAssetType(const std::wstring& filepath) {
    std::wstring lower = filepath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    
    if (lower.find(L"login data") != std::wstring::npos || 
        lower.find(L"logins.json") != std::wstring::npos ||
        lower.find(L"key4.db") != std::wstring::npos) return AssetType::LoginData;
    if (lower.find(L"cookies") != std::wstring::npos) return AssetType::Cookies;
    if (lower.find(L"local state") != std::wstring::npos) return AssetType::LocalState;
    if (lower.find(L"web data") != std::wstring::npos) return AssetType::WebData;
    return AssetType::Unknown;
}

void CredentialMonitor::RecordAccess(uint32_t pid, const std::wstring& filepath) {
    auto now = std::chrono::system_clock::now();
    
    std::string filepath_narrow(filepath.begin(), filepath.end());
    
    AccessEvent event;
    event.timestamp = now;
    event.pid = pid;
    event.parent_pid = 0;
    event.process_path = GetProcessPath(pid);
    event.file_accessed = filepath_narrow;
    event.asset_type = GetAssetType(filepath);
    event.is_browser_process = false;
    event.is_decoy_hit = false;
    
    bool is_new_threat = false;
    if (active_chains_.find(pid) == active_chains_.end()) {
        ThreatChain chain;
        chain.pid = pid;
        chain.process_path = event.process_path;
        chain.first_event = now;
        chain.last_event = now;
        chain.risk_score = 0;
        chain.reported = false;
        active_chains_[pid] = chain;
        is_new_threat = true;
        
        std::cout << "\n!!! CREDENTIAL THEFT DETECTED !!!" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "  PID: " << pid << std::endl;
        std::cout << "  Process: " << event.process_path << std::endl;
        std::cout << "  Target: " << filepath_narrow << std::endl;
        std::cout << "  Asset: ";
        switch (event.asset_type) {
            case AssetType::Cookies: std::cout << "COOKIES (session tokens)"; break;
            case AssetType::LoginData: std::cout << "PASSWORDS"; break;
            case AssetType::LocalState: std::cout << "ENCRYPTION KEY"; break;
            case AssetType::WebData: std::cout << "AUTOFILL DATA"; break;
            default: std::cout << "BROWSER DATA"; break;
        }
        std::cout << std::endl;
    } else {
        std::cout << "\n[THREAT UPDATE] PID " << pid << " accessed: " << filepath_narrow << std::endl;
    }
    
    active_chains_[pid].events.push_back(event);
    active_chains_[pid].last_event = now;
    int old_score = active_chains_[pid].risk_score;
    active_chains_[pid].risk_score = CalculateRiskScore(active_chains_[pid]);
    
    std::cout << "  Files accessed: " << active_chains_[pid].events.size() << std::endl;
    std::cout << "  Risk score: " << old_score << " -> " << active_chains_[pid].risk_score;
    
    std::set<AssetType> types;
    for (const auto& evt : active_chains_[pid].events) {
        types.insert(evt.asset_type);
    }
    std::cout << " (";
    bool first = true;
    if (types.count(AssetType::LoginData)) { if (!first) std::cout << "+"; std::cout << "Pass"; first = false; }
    if (types.count(AssetType::LocalState)) { if (!first) std::cout << "+"; std::cout << "Key"; first = false; }
    if (types.count(AssetType::Cookies)) { if (!first) std::cout << "+"; std::cout << "Cook"; first = false; }
    if (types.count(AssetType::WebData)) { if (!first) std::cout << "+"; std::cout << "Web"; first = false; }
    std::cout << ")" << std::endl;
    
    if (event.asset_type == AssetType::LoginData) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> CRITICAL: PASSWORD FILE ACCESSED" << std::endl;
        std::cout << ">>> TERMINATING IMMEDIATELY (no scoring needed)" << std::endl;
        if (KillProcess(pid)) {
            std::cout << ">>> SUCCESS: Process terminated (PID: " << pid << ")" << std::endl;
        } else {
            std::cout << ">>> FAILURE: Could not terminate - attempting suspension" << std::endl;
            
            HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
            if (hProcess) {
                typedef LONG (NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);
                NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
                    GetModuleHandleA("ntdll"), "NtSuspendProcess");
                if (pfnNtSuspendProcess) {
                    if (pfnNtSuspendProcess(hProcess) == 0) {
                        std::cout << ">>> SUCCESS: Process suspended as fallback" << std::endl;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        std::cout << "========================================\n" << std::endl;
        return;
    }
    
    if (event.asset_type == AssetType::LocalState) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> CRITICAL: ENCRYPTION KEY ACCESSED" << std::endl;
        std::cout << ">>> TERMINATING IMMEDIATELY" << std::endl;
        if (KillProcess(pid)) {
            std::cout << ">>> SUCCESS: Process terminated (PID: " << pid << ")" << std::endl;
        } else {
            std::cout << ">>> FAILURE: Termination denied" << std::endl;
        }
        std::cout << "========================================\n" << std::endl;
        return;
    }
    
    if (active_chains_[pid].risk_score >= 8) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> HIGH RISK THRESHOLD EXCEEDED" << std::endl;
        std::cout << ">>> TERMINATING PROCESS" << std::endl;
        if (KillProcess(pid)) {
            std::cout << ">>> SUCCESS: Process terminated (PID: " << pid << ")" << std::endl;
        } else {
            std::cout << ">>> FAILURE: Could not terminate" << std::endl;
        }
        std::cout << "========================================\n" << std::endl;
    } else {
        std::cout << "  Action: Monitoring (threshold not reached)" << std::endl;
        if (!is_new_threat) {
            std::cout << std::endl;
        }
    }
    
    if (is_new_threat) {
        std::cout << "========================================\n" << std::endl;
    }
}

bool CredentialMonitor::KillProcess(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            return false;
        }
    }
    
    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    if (result) {
        Sleep(50);
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hCheck) {
            active_chains_.erase(pid);
            return true;
        }
        CloseHandle(hCheck);
    }
    
    return result != 0;
}

std::string CredentialMonitor::GetProcessPath(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return "Unknown (PID: " + std::to_string(pid) + ")";
    }
    
    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return std::string(path);
    }
    
    CloseHandle(hProcess);
    return "Unknown (PID: " + std::to_string(pid) + ")";
}

bool CredentialMonitor::IsProcessSuspicious(uint32_t pid) {
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return false;
    if (pid < 500) return false;
    
    std::string path = GetProcessPath(pid);
    if (path.find("Unknown") != std::string::npos) return false;
    
    std::transform(path.begin(), path.end(), path.begin(), ::tolower);
    
    // Browsers
    if (path.find("chrome.exe") != std::string::npos) return false;
    if (path.find("msedge.exe") != std::string::npos) return false;
    if (path.find("firefox.exe") != std::string::npos) return false;
    if (path.find("brave.exe") != std::string::npos) return false;
    if (path.find("opera.exe") != std::string::npos) return false;
    if (path.find("opera gx.exe") != std::string::npos) return false;
    if (path.find("vivaldi.exe") != std::string::npos) return false;
    if (path.find("comet.exe") != std::string::npos) return false;
    
    // Development Tools
    if (path.find("devenv.exe") != std::string::npos) return false;
    if (path.find("code.exe") != std::string::npos) return false;
    if (path.find("codehelper.exe") != std::string::npos) return false;
    if (path.find("msbuild.exe") != std::string::npos) return false;
    if (path.find("vcpkgsrv.exe") != std::string::npos) return false;
    if (path.find("servicehub") != std::string::npos) return false;
    if (path.find("vctip.exe") != std::string::npos) return false;
    if (path.find("perfwatson") != std::string::npos) return false;
    if (path.find("vshost.exe") != std::string::npos) return false;
    if (path.find("dotnet.exe") != std::string::npos) return false;
    if (path.find("powershell.exe") != std::string::npos) return false;
    if (path.find("pwsh.exe") != std::string::npos) return false;
    if (path.find("git.exe") != std::string::npos) return false;
    if (path.find("githubdesktop.exe") != std::string::npos) return false;
    if (path.find("sqlwriter.exe") != std::string::npos) return false;
    if (path.find("diagnosticshub") != std::string::npos) return false;
    if (path.find("standardcollector") != std::string::npos) return false;
    if (path.find("codex.exe") != std::string::npos) return false;
    if (path.find(".vscode") != std::string::npos) return false;
    
    // Graphics/GPU
    if (path.find("nvcontainer.exe") != std::string::npos) return false;
    if (path.find("nvsphelper") != std::string::npos) return false;
    if (path.find("nvidia") != std::string::npos) return false;
    if (path.find("radeonsoftware") != std::string::npos) return false;
    if (path.find("amdryzenmaster") != std::string::npos) return false;
    if (path.find("intelgraphics") != std::string::npos) return false;
    
    // Hardware/RGB/Peripherals
    if (path.find("openrgb.exe") != std::string::npos) return false;
    if (path.find("fancontrol.exe") != std::string::npos) return false;
    if (path.find("steelseries") != std::string::npos) return false;
    if (path.find("redragon") != std::string::npos) return false;
    if (path.find("mouse drive") != std::string::npos) return false;
    if (path.find("corsair") != std::string::npos) return false;
    if (path.find("razer") != std::string::npos) return false;
    if (path.find("logitech") != std::string::npos) return false;
    
    // Communication
    if (path.find("discord.exe") != std::string::npos) return false;
    if (path.find("discordsystemhelper") != std::string::npos) return false;
    if (path.find("discord_updater") != std::string::npos) return false;
    if (path.find("slack.exe") != std::string::npos) return false;
    if (path.find("teams.exe") != std::string::npos) return false;
    if (path.find("skype.exe") != std::string::npos) return false;
    if (path.find("zoom.exe") != std::string::npos) return false;
    if (path.find("signal.exe") != std::string::npos) return false;
    if (path.find("telegram.exe") != std::string::npos) return false;
    
    // Gaming
    if (path.find("steam.exe") != std::string::npos) return false;
    if (path.find("steamservice") != std::string::npos) return false;
    if (path.find("steamwebhelper") != std::string::npos) return false;
    if (path.find("epicgameslauncher") != std::string::npos) return false;
    if (path.find("ubisoftconnect") != std::string::npos) return false;
    if (path.find("origin.exe") != std::string::npos) return false;
    if (path.find("riotclient") != std::string::npos) return false;
    if (path.find("battle.net") != std::string::npos) return false;
    if (path.find("goggalaxy") != std::string::npos) return false;
    if (path.find("wallpaper64.exe") != std::string::npos) return false;
    
    // Music/Media
    if (path.find("spotify.exe") != std::string::npos) return false;
    if (path.find("spotifywebhelper") != std::string::npos) return false;
    if (path.find("itunes.exe") != std::string::npos) return false;
    if (path.find("vlc.exe") != std::string::npos) return false;
    if (path.find("foobar2000") != std::string::npos) return false;
    if (path.find("potplayer") != std::string::npos) return false;
    if (path.find("mediamonkey") != std::string::npos) return false;
    
    // Utilities
    if (path.find("7z.exe") != std::string::npos) return false;
    if (path.find("winrar.exe") != std::string::npos) return false;
    if (path.find("notepad.exe") != std::string::npos) return false;
    if (path.find("notepad++") != std::string::npos) return false;
    if (path.find("sumatrapdf") != std::string::npos) return false;
    if (path.find("paint.net") != std::string::npos) return false;
    if (path.find("gimp") != std::string::npos) return false;
    if (path.find("photoshop") != std::string::npos) return false;
    if (path.find("lightroom") != std::string::npos) return false;
    if (path.find("blender") != std::string::npos) return false;
    if (path.find("everything.exe") != std::string::npos) return false;
    
    // VPN Services
    if (path.find("nordvpn") != std::string::npos) return false;
    if (path.find("openvpn") != std::string::npos) return false;
    if (path.find("protonvpn") != std::string::npos) return false;
    if (path.find("expressvpn") != std::string::npos) return false;
    if (path.find("surfshark") != std::string::npos) return false;
    
    // Antivirus
    if (path.find("msmpeng") != std::string::npos) return false;
    if (path.find("avast") != std::string::npos) return false;
    if (path.find("avira") != std::string::npos) return false;
    if (path.find("kaspersky") != std::string::npos) return false;
    if (path.find("bitdefender") != std::string::npos) return false;
    
    // Argus itself
    if (path.find("argus.exe") != std::string::npos) return false;
    
    // Windows System
    if (path.find("system32") != std::string::npos) return false;
    if (path.find("\\windows\\") != std::string::npos) return false;
    if (path.find("\\microsoft\\") != std::string::npos) return false;
    if (path.find("windowsapps") != std::string::npos) return false;
    if (path.find("svchost") != std::string::npos) return false;
    if (path.find("csrss") != std::string::npos) return false;
    if (path.find("lsass") != std::string::npos) return false;
    if (path.find("services") != std::string::npos) return false;
    if (path.find("smss") != std::string::npos) return false;
    if (path.find("wininit") != std::string::npos) return false;
    if (path.find("dwm") != std::string::npos) return false;
    if (path.find("explorer.exe") != std::string::npos) return false;
    if (path.find("searchhost") != std::string::npos) return false;
    if (path.find("runtimebroker") != std::string::npos) return false;
    if (path.find("applicationframehost") != std::string::npos) return false;
    if (path.find("antimalware") != std::string::npos) return false;
    if (path.find("defender") != std::string::npos) return false;
    if (path.find("securityhealth") != std::string::npos) return false;
    if (path.find("taskhostw") != std::string::npos) return false;
    if (path.find("conhost") != std::string::npos) return false;
    if (path.find("backgroundtaskhost") != std::string::npos) return false;
    if (path.find("taskmgr") != std::string::npos) return false;
    
    return true;
}

void CredentialMonitor::AnalyzeAccessPatterns() {
    auto now = std::chrono::system_clock::now();
    
    for (auto& pair : active_chains_) {
        pair.second.risk_score = CalculateRiskScore(pair.second);
    }
    
    std::vector<uint32_t> expired_pids;
    for (auto& pair : active_chains_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.last_event).count();
        if (age > 300) {
            expired_pids.push_back(pair.first);
        }
    }
    
    for (uint32_t pid : expired_pids) {
        active_chains_.erase(pid);
    }
}

int CredentialMonitor::CalculateRiskScore(const ThreatChain& chain) {
    int score = 0;
    
    std::set<AssetType> accessed_types;
    for (const auto& event : chain.events) {
        accessed_types.insert(event.asset_type);
        if (event.is_decoy_hit) score += 10;
        
        if (event.asset_type == AssetType::LoginData) {
            score += 20;
        }
    }
    
    if (accessed_types.count(AssetType::Cookies)) score += 3;
    if (accessed_types.count(AssetType::LocalState)) score += 4;
    if (accessed_types.count(AssetType::WebData)) score += 2;
    
    if (accessed_types.size() >= 2) score += 5;
    if (accessed_types.size() >= 3) score += 5;
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        chain.last_event - chain.first_event).count();
    if (duration <= 30) score += 3;
    
    return score;
}

}



