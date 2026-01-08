#include "credential_monitor.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <set>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

typedef VOID (NTAPI *PIO_APC_ROUTINE_CUSTOM)(
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Reserved
);

extern "C" NTSTATUS NTAPI NtNotifyChangeDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE_CUSTOM ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    ULONG CompletionFilter,
    BOOLEAN WatchTree
);

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
    : is_active_(false), session_handle_(0), trace_handle_(0), etw_running_(false), 
      polling_thread_(NULL), temp_watcher_thread_(NULL) {
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
    
    file_identity_tracker_.Initialize();
    PreventionLogger::Initialize();
    
    polling_thread_ = CreateThread(NULL, 0, PollingThread, this, 0, NULL);
    temp_watcher_thread_ = CreateThread(NULL, 0, TempFileWatcherThread, this, 0, NULL);
    
    std::cout << "[CredentialMonitor] Real-time monitoring + identity tracking + forensic logging active" << std::endl;
    
    return true;
}

void CredentialMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    etw_running_ = false;
    StopDirectoryWatchers();
    StopETWSession();
    
    if (polling_thread_) {
        WaitForSingleObject(polling_thread_, 2000);
        CloseHandle(polling_thread_);
        polling_thread_ = NULL;
    }
    
    if (temp_watcher_thread_) {
        WaitForSingleObject(temp_watcher_thread_, 2000);
        CloseHandle(temp_watcher_thread_);
        temp_watcher_thread_ = NULL;
    }
    
    file_identity_tracker_.Shutdown();
    
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
    
    if (!s_instance) {
        CloseHandle(hDir);
        delete directory;
        return 1;
    }
    
    HANDLE hCompletion = CreateIoCompletionPort(hDir, NULL, (ULONG_PTR)hDir, 1);
    if (!hCompletion) {
        CloseHandle(hDir);
        delete directory;
        return 1;
    }
    
    char buffer[65536];
    IO_STATUS_BLOCK iosb;
    
    while (s_instance->etw_running_) {
        ZeroMemory(&iosb, sizeof(iosb));
        ZeroMemory(buffer, sizeof(buffer));
        
        NTSTATUS status = NtNotifyChangeDirectoryFile(
            hDir,
            hCompletion,
            NULL,
            NULL,
            &iosb,
            buffer,
            sizeof(buffer),
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_ACCESS | 
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | 
            FILE_NOTIFY_CHANGE_CREATION,
            TRUE
        );
        
        if (status != 0 && status != 0x103) {
            break;
        }
        
        DWORD bytesTransferred = 0;
        ULONG_PTR completionKey = 0;
        LPOVERLAPPED pOverlapped = NULL;
        
        if (GetQueuedCompletionStatus(hCompletion, &bytesTransferred, &completionKey, &pOverlapped, 50)) {
            if (bytesTransferred > 0) {
                FILE_NOTIFY_INFORMATION* info = (FILE_NOTIFY_INFORMATION*)buffer;
                
                std::vector<std::wstring> critical_files;
                
                do {
                    std::wstring filename(info->FileName, info->FileNameLength / sizeof(WCHAR));
                    std::wstring fullPath = wDirectory + L"\\" + filename;
                    
                    std::wstring lower = fullPath;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                    
                    if (lower.find(L"login data") != std::wstring::npos ||
                        lower.find(L"local state") != std::wstring::npos ||
                        lower.find(L"cookies") != std::wstring::npos ||
                        lower.find(L"web data") != std::wstring::npos) {
                        critical_files.push_back(fullPath);
                    }
                    
                    if (info->NextEntryOffset == 0) break;
                    info = (FILE_NOTIFY_INFORMATION*)((BYTE*)info + info->NextEntryOffset);
                } while (true);
                
                if (!critical_files.empty()) {
                    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (snapshot != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe32;
                        pe32.dwSize = sizeof(PROCESSENTRY32W);
                        
                        std::vector<uint32_t> all_suspicious;
                        
                        if (Process32FirstW(snapshot, &pe32)) {
                            do {
                                if (s_instance->IsProcessSuspicious(pe32.th32ProcessID)) {
                                    all_suspicious.push_back(pe32.th32ProcessID);
                                }
                            } while (Process32NextW(snapshot, &pe32));
                        }
                        CloseHandle(snapshot);
                        
                        for (const auto& filepath : critical_files) {
                            HANDLE hFile = CreateFileW(
                                filepath.c_str(),
                                GENERIC_READ,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL
                            );
                            
                            if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION) {
                                for (uint32_t pid : all_suspicious) {
                                    std::lock_guard<std::mutex> lock(s_instance->chains_mutex_);
                                    s_instance->RecordAccess(pid, filepath);
                                }
                                break;
                            }
                            
                            if (hFile != INVALID_HANDLE_VALUE) {
                                CloseHandle(hFile);
                            }
                            
                            for (uint32_t pid : all_suspicious) {
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
                                        if (age_seconds < 120) {
                                            std::lock_guard<std::mutex> lock(s_instance->chains_mutex_);
                                            s_instance->RecordAccess(pid, filepath);
                                            break;
                                        }
                                    }
                                    CloseHandle(hProcess);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    CloseHandle(hCompletion);
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

DWORD WINAPI CredentialMonitor::PollingThread(LPVOID param) {
    CredentialMonitor* monitor = (CredentialMonitor*)param;
    
    while (monitor->etw_running_) {
        monitor->CheckFileChanges();
        Sleep(10);
    }
    
    return 0;
}

DWORD WINAPI CredentialMonitor::TempFileWatcherThread(LPVOID param) {
    CredentialMonitor* monitor = (CredentialMonitor*)param;
    
    char tempPath[MAX_PATH];
    DWORD tempPathLen = GetTempPathA(MAX_PATH, tempPath);
    if (tempPathLen == 0) {
        return 1;
    }
    
    std::wstring wTempPath(tempPath, tempPath + tempPathLen);
    
    HANDLE hDir = CreateFileW(
        wTempPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (hDir == INVALID_HANDLE_VALUE) {
        return 1;
    }
    
    HANDLE hCompletion = CreateIoCompletionPort(hDir, NULL, (ULONG_PTR)hDir, 1);
    if (!hCompletion) {
        CloseHandle(hDir);
        return 1;
    }
    
    char buffer[65536];
    IO_STATUS_BLOCK iosb;
    
    while (monitor->etw_running_) {
        ZeroMemory(&iosb, sizeof(iosb));
        ZeroMemory(buffer, sizeof(buffer));
        
        NTSTATUS status = NtNotifyChangeDirectoryFile(
            hDir,
            hCompletion,
            NULL,
            NULL,
            &iosb,
            buffer,
            sizeof(buffer),
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION,
            TRUE
        );
        
        if (status != 0 && status != 0x103) {
            break;
        }
        
        DWORD bytesTransferred = 0;
        ULONG_PTR completionKey = 0;
        LPOVERLAPPED pOverlapped = NULL;
        
        if (GetQueuedCompletionStatus(hCompletion, &bytesTransferred, &completionKey, &pOverlapped, 50)) {
            if (bytesTransferred > 0) {
                FILE_NOTIFY_INFORMATION* info = (FILE_NOTIFY_INFORMATION*)buffer;
                
                do {
                    std::wstring filename(info->FileName, info->FileNameLength / sizeof(WCHAR));
                    std::wstring fullPath = wTempPath + filename;
                    
                    std::wstring lower = fullPath;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                    
                    bool is_sqlite = (lower.find(L".db") != std::wstring::npos ||
                                     lower.find(L".sqlite") != std::wstring::npos ||
                                     lower.find(L"-journal") != std::wstring::npos ||
                                     lower.find(L"-wal") != std::wstring::npos ||
                                     lower.find(L".db-shm") != std::wstring::npos);
                    
                    bool is_suspicious = (lower.find(L"temp") != std::wstring::npos ||
                                         lower.find(L"cookie") != std::wstring::npos ||
                                         lower.find(L"login") != std::wstring::npos ||
                                         lower.find(L"password") != std::wstring::npos ||
                                         lower.find(L"staging") != std::wstring::npos ||
                                         lower.find(L"dump") != std::wstring::npos);
                    
                    if (is_sqlite && is_suspicious) {
                        Sleep(5);
                        
                        std::string fullPath_narrow(fullPath.begin(), fullPath.end());
                        
                        HANDLE hFile = CreateFileW(
                            fullPath.c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL
                        );
                        
                        if (hFile != INVALID_HANDLE_VALUE) {
                            char junk[4096];
                            for (int i = 0; i < sizeof(junk); i++) {
                                junk[i] = (char)(rand() % 256);
                            }
                            
                            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                            DWORD written = 0;
                            WriteFile(hFile, junk, sizeof(junk), &written, NULL);
                            
                            SetEndOfFile(hFile);
                            FlushFileBuffers(hFile);
                            
                            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                            if (snapshot != INVALID_HANDLE_VALUE) {
                                PROCESSENTRY32W pe32;
                                pe32.dwSize = sizeof(PROCESSENTRY32W);
                                
                                if (Process32FirstW(snapshot, &pe32)) {
                                    do {
                                        if (monitor->IsProcessSuspicious(pe32.th32ProcessID)) {
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
                                                    if (age_seconds < 30) {
                                                        monitor->file_identity_tracker_.RecordFileWrite(pe32.th32ProcessID, fullPath_narrow);
                                                        
                                                        ProcessActivity* activity = monitor->file_identity_tracker_.GetProcessActivity(pe32.th32ProcessID);
                                                        if (activity && activity->file_accesses.size() > 0) {
                                                            std::cout << "\n!!! TEMP DB NEUTRALIZED !!!" << std::endl;
                                                            std::cout << "========================================" << std::endl;
                                                            std::cout << "  PID: " << pe32.th32ProcessID << std::endl;
                                                            std::cout << "  Process: " << activity->process_path << std::endl;
                                                            std::cout << "  Temp File: " << fullPath_narrow << std::endl;
                                                            std::cout << "  Action: CORRUPTED + LOCKED" << std::endl;
                                                            std::cout << "  Behavior Score: " << activity->behavior_score << std::endl;
                                                            
                                                            if (activity->behavior_score >= 60) {
                                                                std::cout << ">>> TERMINATING PROCESS" << std::endl;
                                                                if (monitor->KillProcess(pe32.th32ProcessID)) {
                                                                    std::cout << ">>> SUCCESS: Process terminated" << std::endl;
                                                                } else {
                                                                    std::cout << ">>> FAILURE: Termination denied (file still neutralized)" << std::endl;
                                                                }
                                                            } else {
                                                                std::cout << "  File neutralized, monitoring continues" << std::endl;
                                                            }
                                                            std::cout << "========================================\n" << std::endl;
                                                        }
                                                        break;
                                                    }
                                                }
                                                CloseHandle(hProcess);
                                            }
                                        }
                                    } while (Process32NextW(snapshot, &pe32));
                                }
                                CloseHandle(snapshot);
                            }
                            
                            CloseHandle(hFile);
                        }
                    }
                    
                    if (info->NextEntryOffset == 0) break;
                    info = (FILE_NOTIFY_INFORMATION*)((BYTE*)info + info->NextEntryOffset);
                } while (true);
            }
        }
    }
    
    CloseHandle(hCompletion);
    CloseHandle(hDir);
    return 0;
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
            
            std::string logical_type;
            switch (type) {
                case AssetType::Cookies: logical_type = "cookies"; break;
                case AssetType::LoginData: logical_type = "passwords"; break;
                case AssetType::LocalState: logical_type = "masterkey"; break;
                case AssetType::WebData: logical_type = "autofill"; break;
                default: logical_type = "unknown"; break;
            }
            
            if (file_identity_tracker_.RegisterFile(full_path, browser, profile_path, logical_type)) {
                status.files_monitored++;
            }
            status.files_found++;
            
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
    
    std::lock_guard<std::mutex> lock(chains_mutex_);
    AnalyzeAccessPatterns();
}

void CredentialMonitor::CheckFileChanges() {
    for (auto& pair : file_snapshots_) {
        const std::string& path = pair.first;
        FileSnapshot& old_snap = pair.second;
        
        struct _stat64 statbuf;
        if (_stat64(path.c_str(), &statbuf) == 0) {
            bool accessed = (statbuf.st_atime != old_snap.last_access);
            bool modified = (statbuf.st_mtime != old_snap.last_modify);
            bool size_changed = (statbuf.st_size != old_snap.size);
            
            if (accessed || modified || size_changed) {
                std::wstring wpath(path.begin(), path.end());
                
                std::string lower_path = path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
                
                bool is_critical = (lower_path.find("login data") != std::string::npos ||
                                   lower_path.find("local state") != std::string::npos ||
                                   lower_path.find("cookies") != std::string::npos);
                
                std::vector<uint32_t> suspicious_pids;
                
                HANDLE hFile = CreateFileA(
                    path.c_str(),
                    GENERIC_READ,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                );
                
                if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION) {
                    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (snapshot != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe32;
                        pe32.dwSize = sizeof(PROCESSENTRY32W);
                        
                        if (Process32FirstW(snapshot, &pe32)) {
                            do {
                                if (IsProcessSuspicious(pe32.th32ProcessID)) {
                                    suspicious_pids.push_back(pe32.th32ProcessID);
                                }
                            } while (Process32NextW(snapshot, &pe32));
                        }
                        CloseHandle(snapshot);
                    }
                } else {
                    if (hFile != INVALID_HANDLE_VALUE) {
                        CloseHandle(hFile);
                    }
                    
                    if (is_critical) {
                        suspicious_pids = GetRecentProcesses();
                    }
                }
                
                if (!suspicious_pids.empty()) {
                    for (uint32_t pid : suspicious_pids) {
                        std::lock_guard<std::mutex> lock(chains_mutex_);
                        RecordAccess(pid, wpath);
                        
                        if (is_critical) {
                            break;
                        }
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
                        if (age_seconds < 120) {
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
    if (lower.find(L"local state") != std::wstring::npos) return AssetType::LocalState;
    if (lower.find(L"cookies-journal") != std::wstring::npos) return AssetType::Cookies;
    if (lower.find(L"cookies") != std::wstring::npos) return AssetType::Cookies;
    if (lower.find(L"web data") != std::wstring::npos) return AssetType::WebData;
    return AssetType::Unknown;
}

void CredentialMonitor::RecordAccess(uint32_t pid, const std::wstring& filepath) {
auto now = std::chrono::system_clock::now();
    
std::string filepath_narrow(filepath.begin(), filepath.end());
    
std::string lower_narrow = filepath_narrow;
std::transform(lower_narrow.begin(), lower_narrow.end(), lower_narrow.begin(), ::tolower);
    
uint64_t file_id = 0;
uint32_t volume_serial = 0;
bool has_identity = file_identity_tracker_.GetFileIdentity(filepath_narrow, file_id, volume_serial);
    
bool is_indirect = has_identity && file_identity_tracker_.IsReparsePoint(filepath_narrow);
    
    if (has_identity) {
        file_identity_tracker_.RecordFileAccess(pid, filepath_narrow, file_id, volume_serial, is_indirect);
        
        ProcessActivity* activity = file_identity_tracker_.GetProcessActivity(pid);
        if (activity) {
            if (activity->has_temp_staging) {
                std::cout << "\n!!! CRITICAL: STAGING + CREDENTIAL ACCESS !!!" << std::endl;
                std::cout << "Behavior Score: " << activity->behavior_score << std::endl;
                std::cout << "Temp DB Files: " << activity->temp_db_files.size() << std::endl;
                for (const auto& temp_file : activity->temp_db_files) {
                    std::cout << "  - " << temp_file << std::endl;
                }
                std::cout << ">>> TERMINATING IMMEDIATELY" << std::endl;
                if (KillProcess(pid)) {
                    std::cout << ">>> SUCCESS: Staging process terminated" << std::endl;
                } else {
                    std::cout << ">>> FAILURE: Could not terminate" << std::endl;
                }
                std::cout << std::endl;
            } else if (activity->behavior_score >= 90) {
                std::cout << "\n!!! HIGH RISK BEHAVIOR DETECTED !!!" << std::endl;
                std::cout << "Behavior Score: " << activity->behavior_score << std::endl;
                std::cout << "Classification: ";
                if (activity->behavior_score >= 120) {
                    std::cout << "CONFIRMED CREDENTIAL THEFT" << std::endl;
                    std::cout << ">>> TERMINATING IMMEDIATELY" << std::endl;
                    if (KillProcess(pid)) {
                        std::cout << ">>> SUCCESS: Process terminated" << std::endl;
                    }
                } else {
                    std::cout << "HIGH RISK ACTIVITY" << std::endl;
                }
                std::cout << std::endl;
            }
        }
    }
    
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
        
    std::cout << "\n!!! CREDENTIAL THEFT ATTEMPT DETECTED !!!" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  PID: " << pid << std::endl;
    std::cout << "  Process: " << event.process_path << std::endl;
    std::cout << "  Target: " << filepath_narrow << std::endl;
        
    if (is_indirect) {
        std::cout << "  Access Type: INDIRECT (via reparse point)" << std::endl;
        std::cout << "  Evasion Technique: Symlink/Junction/Hardlink" << std::endl;
    }
        
    if (has_identity) {
        FileIdentity* identity = file_identity_tracker_.GetFileIdentity(file_id, volume_serial);
        if (identity) {
            std::cout << "  Canonical Path: " << identity->canonical_path << std::endl;
            std::cout << "  File Identity: " << identity->logical_type << std::endl;
        }
    }
        
    std::cout << "  Asset: ";
    switch (event.asset_type) {
        case AssetType::Cookies: 
            if (lower_narrow.find("cookies-journal") != std::string::npos) {
                std::cout << "COOKIES-JOURNAL (auth requests)";
            } else {
                std::cout << "COOKIES (session tokens)";
            }
            break;
        case AssetType::LoginData: std::cout << "PASSWORDS"; break;
        case AssetType::LocalState: std::cout << "ENCRYPTION KEY"; break;
        case AssetType::WebData: std::cout << "AUTOFILL DATA"; break;
        default: std::cout << "BROWSER DATA"; break;
    }
    std::cout << std::endl;
} else {
    std::cout << "\n[THREAT UPDATE] PID " << pid << " accessed: " << filepath_narrow << std::endl;
    if (is_indirect) {
        std::cout << "  [EVASION] Indirect access via reparse point" << std::endl;
    }
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
    
    if (lower_narrow.find("cookies-journal") != std::string::npos) {
        if (is_new_threat) {
            std::cout << "========================================\n" << std::endl;
        }
        return;
    }
    
    if (event.asset_type == AssetType::LoginData) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> CRITICAL: PASSWORD FILE ACCESSED" << std::endl;
        
        std::vector<std::string> accessed_files = {filepath_narrow};
        std::vector<std::string> neutralized_files;
        
        ProcessActivity* activity = file_identity_tracker_.GetProcessActivity(pid);
        if (activity) {
            for (const auto& temp_file : activity->temp_db_files) {
                FileNeutralizer::NeutralizeFile(temp_file);
                neutralized_files.push_back(temp_file);
            }
            for (const auto& file_write : activity->file_writes) {
                std::string lower = file_write;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.find(".db") != std::string::npos || lower.find(".sqlite") != std::string::npos) {
                    FileNeutralizer::NeutralizeFile(file_write);
                    neutralized_files.push_back(file_write);
                }
            }
        }
        
        std::string event_id = PreventionLogger::LogPrevention(
            pid, event.process_path, "SQLITE_CREDENTIAL_EXTRACTION", accessed_files, neutralized_files);
        
        if (KillProcess(pid)) {
            std::cout << ">>> SUCCESS: Process terminated" << std::endl;
            FileNeutralizer::ContinuousScanAndNeutralize(pid, event.process_path, event_id, 3000);
            FileNeutralizer::DeepScanAndNeutralize(pid, event.process_path, event_id);
        }
        
        PreventionLogger::DisplayPreventionCertificate(event_id);
        return;
    }
    
    if (event.asset_type == AssetType::LocalState) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> CRITICAL: MASTER KEY ACCESSED" << std::endl;
        
        std::vector<std::string> accessed_files = {filepath_narrow};
        std::vector<std::string> neutralized_files;
        
        std::string event_id = PreventionLogger::LogPrevention(
            pid, event.process_path, "MASTER_KEY_EXTRACTION", accessed_files, neutralized_files);
        
        if (KillProcess(pid)) {
            std::cout << ">>> SUCCESS: Process terminated" << std::endl;
            FileNeutralizer::ContinuousScanAndNeutralize(pid, event.process_path, event_id, 3000);
            FileNeutralizer::DeepScanAndNeutralize(pid, event.process_path, event_id);
        }
        
        PreventionLogger::DisplayPreventionCertificate(event_id);
        return;
    }
    
    if (event.asset_type == AssetType::Cookies && active_chains_[pid].risk_score >= 10) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> CRITICAL: SUSPICIOUS COOKIE ACCESS" << std::endl;
        
        std::vector<std::string> accessed_files = {filepath_narrow};
        std::vector<std::string> neutralized_files;
        
        std::string event_id = PreventionLogger::LogPrevention(
            pid, event.process_path, "COOKIE_EXTRACTION", accessed_files, neutralized_files);
        
        if (KillProcess(pid)) {
            std::cout << ">>> SUCCESS: Process terminated" << std::endl;
            FileNeutralizer::ContinuousScanAndNeutralize(pid, event.process_path, event_id, 3000);
            FileNeutralizer::DeepScanAndNeutralize(pid, event.process_path, event_id);
        }
        
        PreventionLogger::DisplayPreventionCertificate(event_id);
        return;
    }
    
    if (active_chains_[pid].risk_score >= 7) {
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
    if (path.find("nordupdater") != std::string::npos) return false;
    if (path.find("nordupdate") != std::string::npos) return false;
    if (path.find("openvpn") != std::string::npos) return false;
    if (path.find("protonvpn") != std::string::npos) return false;
    if (path.find("expressvpn") != std::string::npos) return false;
    if (path.find("surfshark") != std::string::npos) return false;
    
    // Virtualization
    if (path.find("vmware") != std::string::npos) return false;
    if (path.find("virtualbox") != std::string::npos) return false;
    if (path.find("hyper-v") != std::string::npos) return false;
    
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
    bool has_journal = false;
    
    for (const auto& event : chain.events) {
        accessed_types.insert(event.asset_type);
        if (event.is_decoy_hit) score += 10;
        
        std::string lower = event.file_accessed;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("cookies-journal") != std::string::npos) {
            has_journal = true;
        }
        
        if (event.asset_type == AssetType::LoginData) {
            score += 50;
        }
        if (event.asset_type == AssetType::LocalState) {
            score += 40;
        }
    }
    
    if (has_journal && accessed_types.size() == 1 && accessed_types.count(AssetType::Cookies)) {
        return 1;
    }
    
    if (accessed_types.count(AssetType::Cookies)) score += 3;
    if (accessed_types.count(AssetType::WebData)) score += 2;
    
    if (accessed_types.size() >= 2) score += 3;
    if (accessed_types.size() >= 3) score += 5;
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        chain.last_event - chain.first_event).count();
    if (duration <= 10) score += 2;
    
    return score;
}

}



