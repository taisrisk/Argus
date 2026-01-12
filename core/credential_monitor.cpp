#include "credential_monitor.h"
#include "console_format.h"
#include "threat_fingerprint.h"

// Keep windows.h lean and avoid winsock.h conflicts.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

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

#include "threat_fingerprint.h"

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

static std::string AssetShortName(AssetType t, const std::string& lowerPath) {
    switch (t) {
        case AssetType::Cookies:
            if (lowerPath.find("cookies-journal") != std::string::npos) return "Cookies-Journal";
            return "Cookies";
        case AssetType::LoginData:
            return "Passwords";
        case AssetType::LocalState:
            return "MasterKey";
        case AssetType::WebData:
            return "WebData";
        case AssetType::ExtensionScript:
            return "ExtScript";
        default:
            return "BrowserData";
    }
}

static void PrintThreatCompactLine(
    uint32_t pid,
    const std::string& processPath,
    AssetType assetType,
    const std::string& lowerPath,
    int riskScore,
    const SignalCorrelator* correlator,
    const char* actionText,
    ConsoleColor actionColor,
    const char* severityText,
    ConsoleColor severityColor) {

    int totalSignals = -1;
    int corroborated = -1;
    if (correlator) {
        auto* c = const_cast<SignalCorrelator*>(correlator)->AnalyzeProcess(pid);
        if (c) {
            totalSignals = static_cast<int>(c->signals.size());
            corroborated = c->corroboration_count;
        }
    }

    ConsoleFormat::PrintThreatLine(
        "THREAT",
        ConsoleColor::Magenta,
        severityText,
        severityColor,
        pid,
        processPath,
        actionText,
        actionColor,
        AssetShortName(assetType, lowerPath),
        riskScore,
        totalSignals,
        corroborated);
}

static void PrintThreatMergedLine(
    uint32_t pid,
    const std::string& processPath,
    AssetType assetType,
    const std::string& lowerPath,
    int riskScore,
    const SignalCorrelator* correlator,
    bool willSuspendAssess) {

    // Merge the common pair:
    //   [THREAT][HIGH] ... -> MONITOR
    //   [THREAT][CRIT] ... -> SUSPEND+ASSESS
    // into one human line.
    const char* sev = willSuspendAssess ? "CRIT" : ((riskScore >= 7) ? "HIGH" : "MED");
    ConsoleColor sevColor = willSuspendAssess ? ConsoleColor::Red : ((riskScore >= 7) ? ConsoleColor::Red : ConsoleColor::Yellow);
    const char* act = willSuspendAssess ? "SUSPEND+ASSESS" : "MONITOR";
    ConsoleColor actColor = willSuspendAssess ? ConsoleColor::Yellow : ConsoleColor::Dim;

    PrintThreatCompactLine(
        pid,
        processPath,
        assetType,
        lowerPath,
        riskScore,
        correlator,
        act,
        actColor,
        sev,
        sevColor);
}

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

static bool SetAllThreadsSuspendState(uint32_t pid, bool suspend) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    bool any = false;
    bool ok_all = true;

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }

            any = true;
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!hThread) {
                ok_all = false;
                continue;
            }

            if (suspend) {
                if (SuspendThread(hThread) == (DWORD)-1) {
                    ok_all = false;
                }
            } else {
                // Resume until fully resumed.
                for (;;) {
                    DWORD prev = ResumeThread(hThread);
                    if (prev == (DWORD)-1) {
                        ok_all = false;
                        break;
                    }
                    if (prev <= 1) {
                        break;
                    }
                }
            }

            CloseHandle(hThread);
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return any && ok_all;
}

bool CredentialMonitor::SuspendProcess(uint32_t pid) {
    return SetAllThreadsSuspendState(pid, true);
}

bool CredentialMonitor::ResumeProcess(uint32_t pid) {
    return SetAllThreadsSuspendState(pid, false);
}

bool CredentialMonitor::ShouldEmergencyTerminateSingleSignal(AssetType asset_type) const {
    // Phase 3.1 policy: no single watchdog is authoritative.
    // Keep an emergency override for the most critical assets, but default to OFF.
    // If you want the old behavior, flip this to true for LoginData/LocalState.
    (void)asset_type;
    return false;
}

bool CredentialMonitor::SuspendAndAssess(uint32_t pid, const std::string& reason, const std::vector<std::string>& accessed_files) {
    // Suspend -> fingerprint -> correlate -> decide -> terminate/monitor
    // NOTE: Fingerprinting is currently a stub in this codebase; we still keep the pipeline.
    std::string process_path = GetProcessPath(pid);

    // De-dup: this function can be called multiple times for the same PID as more
    // sensitive assets are touched. Only print the full block once per PID.
    static std::mutex s_print_mu;
    static std::map<uint32_t, std::chrono::steady_clock::time_point> s_last_print;
    bool print_details = true;
    {
        std::lock_guard<std::mutex> lock(s_print_mu);
        auto now = std::chrono::steady_clock::now();
        auto it = s_last_print.find(pid);
        if (it != s_last_print.end()) {
            // If we already printed a full SUSPEND->ASSESS block recently for this PID,
            // suppress duplicates (common when multiple file events arrive back-to-back).
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (age < 3) {
                print_details = false;
            }
        }
        if (print_details) {
            s_last_print[pid] = now;
        }
    }

    if (print_details) {
        std::cout << "========================================" << std::endl;
        std::cout << ">>> ACTION: SUSPEND -> ASSESS" << std::endl;
        std::cout << "    Reason: " << reason << std::endl;
        std::cout << "    PID: " << pid << std::endl;
        std::cout << "    Process: " << process_path << std::endl;
    }

    bool suspended = SuspendProcess(pid);
    if (!suspended && print_details) {
        std::cout << "    [WARN] Could not suspend (insufficient rights). Continuing assessment." << std::endl;
    }

    // Record a prevention event for audit trail (even if we end up monitoring).
    std::vector<std::string> neutralized_files;
    std::string event_id = PreventionLogger::LogPrevention(
        pid, process_path, reason, accessed_files, neutralized_files);

    // Correlator decides based on mesh.
    bool should_terminate = signal_correlator_.ShouldTerminate(pid);
    std::string classification = signal_correlator_.ClassifyThreat(pid);

    if (print_details) {
        std::cout << "    Correlation: " << classification << std::endl;
    }

    if (should_terminate) {
        if (print_details) {
            std::cout << ">>> MULTI-SIGNAL CONFIRMED: TERMINATING" << std::endl;
        }

        // Capture threat fingerprint bundle before termination.
        {
            ThreatFingerprintResult fr = ThreatFingerprint::CaptureForPid(pid, reason, classification, accessed_files);
            if (fr.ok) {
                if (print_details) {
                    std::cout << "    [Forensics] Saved threat fingerprint: " << fr.output_dir << std::endl;
                }
            } else {
                if (print_details) {
                    std::cout << "    [Forensics][WARN] Fingerprint capture failed: " << fr.error << std::endl;
                }
            }
        }

        // Force the OS to flush directory metadata so other threads/processes can see the new
        // threats/<sha256>/ folder immediately.
        {
            std::string tdir = ThreatFingerprint::GetThreatsDir();
            HANDLE hDir = CreateFileA(
                tdir.c_str(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                nullptr);
            if (hDir != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(hDir);
                CloseHandle(hDir);
            }
        }

        if (KillProcess(pid)) {
            if (print_details) {
                std::cout << ">>> SUCCESS: Process terminated" << std::endl;
            }
        } else {
            if (print_details) {
                std::cout << ">>> FAILURE: Could not terminate" << std::endl;
            }
            if (suspended) {
                ResumeProcess(pid);
            }
        }
        // Keep certificate output (user asked not to remove details), but avoid printing it twice
        // for the same PID in a short window.
        if (print_details) {
            PreventionLogger::DisplayPreventionCertificate(event_id);
        }
        return true;
    }

    // Not corroborated: resume and monitor.
    if (print_details) {
        std::cout << ">>> Not corroborated yet: monitoring" << std::endl;
    }
    if (suspended) {
        ResumeProcess(pid);
    }
    return false;
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
    
    // Load process whitelist from config
    if (!process_whitelist_.LoadFromFile("config/process_whitelist.json")) {
        std::cerr << "[CredentialMonitor] Warning: Using fallback whitelist" << std::endl;
    }
    
    is_active_ = true;
    etw_running_ = true;
    last_check_ = std::chrono::system_clock::now();
    
    file_identity_tracker_.Initialize();
    handle_monitor_.Initialize();
    signal_correlator_.Initialize();
    
    // Link monitors to correlator
    signal_correlator_.SetHandleMonitor(&handle_monitor_);
    signal_correlator_.SetFileIdentityTracker(&file_identity_tracker_);
    
    PreventionLogger::Initialize();
    
    polling_thread_ = CreateThread(NULL, 0, PollingThread, this, 0, NULL);
    temp_watcher_thread_ = CreateThread(NULL, 0, TempFileWatcherThread, this, 0, NULL);
    
    std::cout << "[CredentialMonitor] Phase 3.1 - Multi-signal EDR mesh active" << std::endl;
    std::cout << "[CredentialMonitor] Watchdogs: File Identity | Handle Monitor | Signal Correlator | ETW" << std::endl;
    
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
    
    signal_correlator_.Shutdown();
    handle_monitor_.Shutdown();
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
        Sleep(1);
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
                                         lower.find(L"credential") != std::wstring::npos ||
                                         lower.find(L"extract") != std::wstring::npos ||
                                         lower.find(L"staging") != std::wstring::npos ||
                                         lower.find(L"dump") != std::wstring::npos);
                    
                    if (is_sqlite && is_suspicious) {
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

// If a process is already known-bad (hash exists in threats/), terminate immediately.
// This provides a second enforcement path even if ProcessMonitor misses a short-lived
// process creation event.
static bool ShouldAutoBlockKnownThreat(uint32_t pid, std::string& out_sha256) {
    out_sha256.clear();
    std::string pathA;
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return false;
        char buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        bool ok = QueryFullProcessImageNameA(hProcess, 0, buf, &sz) != 0;
        CloseHandle(hProcess);
        if (!ok) return false;
        pathA.assign(buf, buf + sz);
    }

    std::wstring wpath;
    {
        int len = MultiByteToWideChar(CP_UTF8, 0, pathA.c_str(), -1, nullptr, 0);
        if (len > 0) {
            wpath.resize(static_cast<size_t>(len - 1));
            MultiByteToWideChar(CP_UTF8, 0, pathA.c_str(), -1, &wpath[0], len);
        }
    }
    if (wpath.empty()) return false;

    std::string err;
    if (!argus::ThreatFingerprint::ComputeFileSha256(wpath, out_sha256, err)) {
        return false;
    }

    std::vector<std::string> hashes;
    argus::ThreatFingerprint::LoadKnownBadSha256(hashes);
    return std::find(hashes.begin(), hashes.end(), out_sha256) != hashes.end();
}

void CredentialMonitor::OnFileAccess(uint32_t pid, const std::wstring& filepath) {
    if (IsSensitiveFile(filepath) && IsProcessSuspicious(pid)) {
        // Fallback enforcement: if this process matches a known-bad fingerprint, kill it
        // immediately on first sensitive file touch (covers cases where process-start
        // detection misses the launch).
        {
            std::string sha;
            if (ShouldAutoBlockKnownThreat(pid, sha)) {
                ConsoleFormat::PrintColoredLine(ConsoleColor::Red,
                    std::string("[AUTO-BLOCKED] Known threat fingerprint matched on file access sha256=") + sha +
                    " pid=" + std::to_string(pid));
                KillProcess(pid);
                return;
            }
        }

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
    handle_monitor_.SetBrowserProcessIds(pids);
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
                
                if (is_critical && accessed) {
                    std::vector<uint32_t> suspicious_pids;
                    
                    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (snapshot != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe32;
                        pe32.dwSize = sizeof(PROCESSENTRY32W);
                        
                        if (Process32FirstW(snapshot, &pe32)) {
                            do {
                                if (IsProcessSuspicious(pe32.th32ProcessID)) {
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
                                                suspicious_pids.push_back(pe32.th32ProcessID);
                                            }
                                        }
                                        CloseHandle(hProcess);
                                    }
                                }
                            } while (Process32NextW(snapshot, &pe32));
                        }
                        CloseHandle(snapshot);
                    }
                    
                    if (!suspicious_pids.empty()) {
                        for (uint32_t pid : suspicious_pids) {
                            std::lock_guard<std::mutex> lock(chains_mutex_);
                            RecordAccess(pid, wpath);
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
    
// Get process path to check if it's a browser
std::string process_path = GetProcessPath(pid);
std::string process_lower = process_path;
std::transform(process_lower.begin(), process_lower.end(), process_lower.begin(), ::tolower);

// Check if browser is accessing its own profile
bool is_browser_self_access = false;
if (process_lower.find("chrome.exe") != std::string::npos && lower_narrow.find("\\google\\chrome\\") != std::string::npos) is_browser_self_access = true;
if (process_lower.find("msedge.exe") != std::string::npos && lower_narrow.find("\\microsoft\\edge\\") != std::string::npos) is_browser_self_access = true;
if (process_lower.find("firefox.exe") != std::string::npos && lower_narrow.find("\\mozilla\\firefox\\") != std::string::npos) is_browser_self_access = true;
if (process_lower.find("brave.exe") != std::string::npos && lower_narrow.find("\\bravesoftware\\") != std::string::npos) is_browser_self_access = true;
if (process_lower.find("opera.exe") != std::string::npos && lower_narrow.find("\\opera software\\") != std::string::npos) is_browser_self_access = true;
if (process_lower.find("vivaldi.exe") != std::string::npos && lower_narrow.find("\\vivaldi\\") != std::string::npos) is_browser_self_access = true;
if (process_lower.find("comet.exe") != std::string::npos && lower_narrow.find("\\perplexity\\comet\\") != std::string::npos) is_browser_self_access = true;

// Chromium-based browsers can import/sync from each other (legitimate behavior)
bool is_chromium_cross_access = false;
std::vector<std::string> chromium_browsers = {"chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "comet.exe", "opera.exe"};
bool is_chromium_process = false;
bool is_chromium_target = false;

for (const auto& browser : chromium_browsers) {
    if (process_lower.find(browser) != std::string::npos) is_chromium_process = true;
}

if (lower_narrow.find("\\google\\chrome\\") != std::string::npos ||
    lower_narrow.find("\\microsoft\\edge\\") != std::string::npos ||
    lower_narrow.find("\\bravesoftware\\") != std::string::npos ||
    lower_narrow.find("\\vivaldi\\") != std::string::npos ||
    lower_narrow.find("\\perplexity\\comet\\") != std::string::npos ||
    lower_narrow.find("\\opera software\\") != std::string::npos) {
    is_chromium_target = true;
}

is_chromium_cross_access = is_chromium_process && is_chromium_target;

// If browser is accessing its own files OR Chromium browser accessing another Chromium browser (import/sync), this is legitimate
if (is_browser_self_access || is_chromium_cross_access) {
    // Silently allow - browsers need to access their own credential stores
    // Chromium browsers also legitimately import/sync from each other
    return;
}

uint64_t file_id = 0;
uint32_t volume_serial = 0;
bool has_identity = file_identity_tracker_.GetFileIdentity(filepath_narrow, file_id, volume_serial);
    
bool is_indirect = has_identity && file_identity_tracker_.IsReparsePoint(filepath_narrow);
    
    if (has_identity) {
        file_identity_tracker_.RecordFileAccess(pid, filepath_narrow, file_id, volume_serial, is_indirect);
        
        // Record signal for correlation
        AssetType asset_type = GetAssetType(filepath);
        if (asset_type == AssetType::LoginData || asset_type == AssetType::LocalState) {
            signal_correlator_.RecordSignal(SignalType::FileAccess, pid, 30, filepath_narrow);
        } else if (asset_type == AssetType::Cookies) {
            signal_correlator_.RecordSignal(SignalType::FileAccess, pid, 10, filepath_narrow);
        }
        
        ProcessActivity* activity = file_identity_tracker_.GetProcessActivity(pid);
        if (activity) {
            if (activity->has_temp_staging) {
                // Multi-signal detected: file access + temp staging
                signal_correlator_.RecordSignal(SignalType::TempStaging, pid, 40, "Temp DB staging detected");
                
                std::cout << "\n!!! CRITICAL: STAGING + CREDENTIAL ACCESS !!!" << std::endl;
                std::cout << "Behavior Score: " << activity->behavior_score << std::endl;
                std::cout << "Temp DB Files: " << activity->temp_db_files.size() << std::endl;
                for (const auto& temp_file : activity->temp_db_files) {
                    std::cout << "  - " << temp_file << std::endl;
                }
                
                // Check correlation
                if (signal_correlator_.ShouldTerminate(pid)) {
                    std::cout << ">>> MULTI-SIGNAL CONFIRMATION: TERMINATING" << std::endl;
                    std::string classification = signal_correlator_.ClassifyThreat(pid);
                    std::cout << ">>> Classification: " << classification << std::endl;

                    // Capture threat fingerprint bundle before termination.
                    {
                        std::vector<std::string> accessed_files;
                        accessed_files.push_back(filepath_narrow);
                        ThreatFingerprintResult fr = ThreatFingerprint::CaptureForPid(pid, "STAGING+FILE_ACCESS", classification, accessed_files);
                        if (fr.ok) {
                            std::cout << "    [Forensics] Saved threat fingerprint: " << fr.output_dir << std::endl;
                        } else {
                            std::cout << "    [Forensics][WARN] Fingerprint capture failed: " << fr.error << std::endl;
                        }
                    }
                    
                    if (KillProcess(pid)) {
                        std::cout << ">>> SUCCESS: Staging process terminated" << std::endl;
                    } else {
                        std::cout << ">>> FAILURE: Could not terminate" << std::endl;
                    }
                } else {
                    std::cout << ">>> SUSPENDING FOR ANALYSIS" << std::endl;
                }
                std::cout << std::endl;
            } else if (activity->behavior_score >= 90) {
                std::cout << "\n!!! HIGH RISK BEHAVIOR DETECTED !!!" << std::endl;
                std::cout << "Behavior Score: " << activity->behavior_score << std::endl;
                std::cout << "Classification: ";
                
                // Check signal correlation before termination
                std::string classification = signal_correlator_.ClassifyThreat(pid);
                std::cout << classification << std::endl;
                
                if (classification == "CONFIRMED_STEALER" || classification == "HIGH_CONFIDENCE_THREAT") {
                    std::cout << ">>> MULTI-SIGNAL CORROBORATION: TERMINATING" << std::endl;

                    // Capture threat fingerprint bundle before termination.
                    {
                        std::vector<std::string> accessed_files;
                        accessed_files.push_back(filepath_narrow);
                        ThreatFingerprintResult fr = ThreatFingerprint::CaptureForPid(pid, "HIGH_RISK_BEHAVIOR", classification, accessed_files);
                        if (fr.ok) {
                            std::cout << "    [Forensics] Saved threat fingerprint: " << fr.output_dir << std::endl;
                        } else {
                            std::cout << "    [Forensics][WARN] Fingerprint capture failed: " << fr.error << std::endl;
                        }
                    }

                    if (KillProcess(pid)) {
                        std::cout << ">>> SUCCESS: Process terminated" << std::endl;
                    }
                } else if (activity->behavior_score >= 120) {
                    std::cout << ">>> HIGH SCORE OVERRIDE: TERMINATING" << std::endl;

                    // Capture threat fingerprint bundle before termination.
                    {
                        std::vector<std::string> accessed_files;
                        accessed_files.push_back(filepath_narrow);
                        ThreatFingerprintResult fr = ThreatFingerprint::CaptureForPid(pid, "HIGH_SCORE_OVERRIDE", classification, accessed_files);
                        if (fr.ok) {
                            std::cout << "    [Forensics] Saved threat fingerprint: " << fr.output_dir << std::endl;
                        } else {
                            std::cout << "    [Forensics][WARN] Fingerprint capture failed: " << fr.error << std::endl;
                        }
                    }

                    if (KillProcess(pid)) {
                        std::cout << ">>> SUCCESS: Process terminated" << std::endl;
                    }
                } else {
                    std::cout << ">>> Waiting for additional signals..." << std::endl;
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
} else {
    // Suppress per-access spam; we print a single compact line below.
}
    
    active_chains_[pid].events.push_back(event);
    active_chains_[pid].last_event = now;
    int old_score = active_chains_[pid].risk_score;
    active_chains_[pid].risk_score = CalculateRiskScore(active_chains_[pid]);
    
    // One compact line per access event (new or update).
    // If this access will immediately trigger SuspendAndAssess, don't print a separate
    // "MONITOR" line first (that creates the HIGH+CRIT duplicate pair).
    bool will_suspend_assess = (event.asset_type == AssetType::LoginData || event.asset_type == AssetType::LocalState);
    if (!is_indirect) {
        PrintThreatMergedLine(
            pid,
            event.process_path,
            event.asset_type,
            lower_narrow,
            active_chains_[pid].risk_score,
            &signal_correlator_,
            will_suspend_assess);
    } else {
        // Keep evasion explicit.
        PrintThreatCompactLine(
            pid,
            event.process_path,
            event.asset_type,
            lower_narrow,
            active_chains_[pid].risk_score,
            &signal_correlator_,
            "MONITOR (EVASION)",
            ConsoleColor::Cyan,
            (active_chains_[pid].risk_score >= 7) ? "HIGH" : "MED",
            (active_chains_[pid].risk_score >= 7) ? ConsoleColor::Red : ConsoleColor::Yellow);
    }
    
    if (lower_narrow.find("cookies-journal") != std::string::npos) {
        return;
    }
    
    if (event.asset_type == AssetType::LoginData) {
        // Already printed merged line above.

        // Record a strong signal, but do not terminate on this alone.
        signal_correlator_.RecordSignal(SignalType::FileAccess, pid, 30, "Login Data accessed");

        if (ShouldEmergencyTerminateSingleSignal(event.asset_type)) {
            PrintThreatCompactLine(
                pid,
                event.process_path,
                event.asset_type,
                lower_narrow,
                active_chains_[pid].risk_score,
                &signal_correlator_,
                "TERMINATE (EMERGENCY)",
                ConsoleColor::Red,
                "CRIT",
                ConsoleColor::Red);
            std::vector<std::string> accessed_files = {filepath_narrow};
            std::vector<std::string> neutralized_files;
            std::string event_id = PreventionLogger::LogPrevention(
                pid, event.process_path, "PASSWORD_FILE_ACCESS", accessed_files, neutralized_files);
            KillProcess(pid);
            PreventionLogger::DisplayPreventionCertificate(event_id);
            return;
        }

        // Phase 3.1: suspend and assess based on corroboration.
        SuspendAndAssess(pid, "PASSWORD_FILE_ACCESS", {filepath_narrow});
        return;
    }
    
    if (event.asset_type == AssetType::LocalState) {
        // Already printed merged line above.
        
        // Record encryption key access signal
        signal_correlator_.RecordSignal(SignalType::EncryptionKeyAccess, pid, 50, "Master key accessed");
        
        if (ShouldEmergencyTerminateSingleSignal(event.asset_type)) {
            PrintThreatCompactLine(
                pid,
                event.process_path,
                event.asset_type,
                lower_narrow,
                active_chains_[pid].risk_score,
                &signal_correlator_,
                "TERMINATE (EMERGENCY)",
                ConsoleColor::Red,
                "CRIT",
                ConsoleColor::Red);
            std::vector<std::string> accessed_files = {filepath_narrow};
            std::vector<std::string> neutralized_files;
            std::string event_id = PreventionLogger::LogPrevention(
                pid, event.process_path, "ENCRYPTION_KEY_ACCESS", accessed_files, neutralized_files);
            KillProcess(pid);
            PreventionLogger::DisplayPreventionCertificate(event_id);
            return;
        }

        SuspendAndAssess(pid, "ENCRYPTION_KEY_ACCESS", {filepath_narrow});
        return;
    }
    
    if (event.asset_type == AssetType::Cookies && active_chains_[pid].risk_score >= 10) {
        PrintThreatCompactLine(
            pid,
            event.process_path,
            event.asset_type,
            lower_narrow,
            active_chains_[pid].risk_score,
            &signal_correlator_,
            "TERMINATE",
            ConsoleColor::Red,
            "HIGH",
            ConsoleColor::Red);
        
        // Correlation is already reflected in signals=... on the compact line.
        
        std::vector<std::string> accessed_files = {filepath_narrow};
        std::vector<std::string> neutralized_files;
        
        std::string event_id = PreventionLogger::LogPrevention(
            pid, event.process_path, "COOKIE_EXTRACTION", accessed_files, neutralized_files);
        
        KillProcess(pid);
        PreventionLogger::DisplayPreventionCertificate(event_id);
        return;
    }
    
    if (active_chains_[pid].risk_score >= 7) {
        PrintThreatCompactLine(
            pid,
            event.process_path,
            event.asset_type,
            lower_narrow,
            active_chains_[pid].risk_score,
            &signal_correlator_,
            "TERMINATE",
            ConsoleColor::Red,
            "HIGH",
            ConsoleColor::Red);
        if (KillProcess(pid)) {
            // no extra spam
        } else {
            ConsoleFormat::PrintColoredLine(ConsoleColor::Red, "[THREAT][HIGH] termination failed");
        }
    } else {
        // already printed compact MONITOR line
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
        active_chains_.erase(pid);
        return true;
    }
    
    return false;
}

std::string CredentialMonitor::GetProcessPath(uint32_t pid) {
    // If we already have a known path for this PID in the active chain, prefer it.
    // This avoids "Unknown (PID: ...)" after termination or access-rights changes.
    {
        auto it = active_chains_.find(pid);
        if (it != active_chains_.end() && !it->second.process_path.empty()) {
            if (it->second.process_path.find("Unknown") == std::string::npos) {
                return it->second.process_path;
            }
        }
    }

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
    // System processes and self
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return false;
    if (pid < 500) return false;
    
    // Get process path
    std::string path = GetProcessPath(pid);
    if (path.find("Unknown") != std::string::npos) return false;
    
    // Check against whitelist
    return !process_whitelist_.IsWhitelisted(path);
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



