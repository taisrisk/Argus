#include "extension_scanner.h"

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
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>

namespace argus {

ExtensionScanner::ExtensionScanner() 
    : is_active_(false), user_consent_(false), initial_scan_complete_(false), activity_monitoring_active_(false), watcher_running_(false) {
}

ExtensionScanner::~ExtensionScanner() {
    if (is_active_) {
        Shutdown();
    }
}

bool ExtensionScanner::Initialize(bool user_consent) {
    if (is_active_) {
        return false;
    }
    
    user_consent_ = user_consent;
    is_active_ = true;
    
    return true;
}

void ExtensionScanner::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    StopActivityMonitoring();
    
    is_active_ = false;
    findings_.clear();
    activity_events_.clear();
    monitored_extensions_.clear();
}

void ExtensionScanner::RecordActivityEvent(const std::string& ext_id,
                                          const std::string& ext_name,
                                          const std::string& file_path,
                                          const std::string& change_type) {
    ExtensionActivityEvent evt;
    evt.extension_id = ext_id;
    evt.extension_name = ext_name;
    evt.file_path = file_path;
    evt.change_type = change_type;
    evt.timestamp = std::chrono::system_clock::now();
    activity_events_.push_back(evt);

    const size_t max_events = 500;
    if (activity_events_.size() > max_events) {
        activity_events_.erase(activity_events_.begin(), activity_events_.begin() + (activity_events_.size() - max_events));
    }
}

void ExtensionScanner::PerformInitialScan(const std::string& browser_profile_path) {
if (!is_active_ || !user_consent_) {
    return;
}
    
std::cout << "[ExtensionScanner] Scanning extensions at browser startup..." << std::endl;
    
    std::string extensions_path = browser_profile_path + "\\Extensions";
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((extensions_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != ".." && dir_name != "Temp") {
                std::string ext_path = extensions_path + "\\" + dir_name;
                ScanExtensionOnBrowserStart(ext_path, dir_name);
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
}

void ExtensionScanner::ScanExtensions(const std::string& browser_profile_path) {
    if (!is_active_ || !user_consent_) {
        return;
    }
    
    std::string extensions_path = browser_profile_path + "\\Extensions";
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((extensions_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != ".." && dir_name != "Temp") {
                ScanExtensionDirectory(extensions_path + "\\" + dir_name);
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
}

std::vector<ExtensionFinding> ExtensionScanner::GetFindings() {
    return findings_;
}

void ExtensionScanner::ClearFindings() {
    findings_.clear();
}

void ExtensionScanner::ScanExtensionDirectory(const std::string& ext_path) {
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((ext_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    std::string ext_id;
    size_t last_slash = ext_path.find_last_of("\\");
    if (last_slash != std::string::npos) {
        ext_id = ext_path.substr(last_slash + 1);
    }
    
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != "..") {
                std::string manifest_path = ext_path + "\\" + dir_name + "\\manifest.json";
                
                WIN32_FIND_DATAA manifest_find;
                HANDLE hManifest = FindFirstFileA(manifest_path.c_str(), &manifest_find);
                if (hManifest != INVALID_HANDLE_VALUE) {
                    FindClose(hManifest);
                    AnalyzeManifest(manifest_path, ext_id);
                    break;
                }
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
}

void ExtensionScanner::AnalyzeManifest(const std::string& manifest_path, const std::string& ext_id) {
    std::ifstream file(manifest_path);
    if (!file.is_open()) {
        return;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    ExtensionFinding finding;
    finding.extension_id = ext_id;
    finding.file_path = manifest_path;
    finding.timestamp = std::chrono::system_clock::now();
    
    size_t name_pos = content.find("\"name\"");
    if (name_pos != std::string::npos) {
        size_t start = content.find(":", name_pos) + 1;
        size_t quote1 = content.find("\"", start);
        size_t quote2 = content.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            finding.extension_name = content.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }
    
    if (finding.extension_name.empty() || finding.extension_name.find("__MSG_") == 0) {
        return;
    }
    
    std::string lower_name = finding.extension_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("proton vpn") != std::string::npos ||
        lower_name.find("protonvpn") != std::string::npos ||
        lower_name.find("nordvpn") != std::string::npos ||
        lower_name.find("expressvpn") != std::string::npos ||
        lower_name.find("surfshark") != std::string::npos ||
        lower_name.find("mullvad") != std::string::npos ||
        lower_name.find("windscribe") != std::string::npos ||
        lower_name.find("cyberghost") != std::string::npos ||
        lower_name.find("tunnelbear") != std::string::npos ||
        lower_name.find("private internet access") != std::string::npos ||
        lower_name.find("vyprvpn") != std::string::npos) {
        return;
    }
    
    if (lower_name.find("comet") != std::string::npos ||
        lower_name.find("perplexity") != std::string::npos) {
        return;
    }
    
    std::vector<std::string> high_risk_perms = {
        "webRequestBlocking", "debugger", "proxy"
    };
    
    std::vector<std::string> medium_risk_perms = {
        "<all_urls>", "webRequest"
    };
    
    std::vector<std::string> found_high;
    std::vector<std::string> found_medium;
    
    for (const auto& perm : high_risk_perms) {
        if (content.find(perm) != std::string::npos) {
            found_high.push_back(perm);
        }
    }
    
    for (const auto& perm : medium_risk_perms) {
        if (content.find(perm) != std::string::npos) {
            found_medium.push_back(perm);
        }
    }
    
    if (!found_high.empty()) {
        finding.risk_level = RiskLevel::High;
        finding.pattern_matched = "High-risk permissions: ";
        for (size_t i = 0; i < found_high.size(); ++i) {
            finding.pattern_matched += found_high[i];
            if (i < found_high.size() - 1) finding.pattern_matched += ", ";
        }
        finding.explanation = "Extension can intercept/modify all web traffic";
        findings_.push_back(finding);
    } else if (found_medium.size() >= 2) {
        finding.risk_level = RiskLevel::Medium;
        finding.pattern_matched = "Broad permissions: ";
        for (size_t i = 0; i < found_medium.size(); ++i) {
            finding.pattern_matched += found_medium[i];
            if (i < found_medium.size() - 1) finding.pattern_matched += ", ";
        }
        finding.explanation = "Extension has broad access to browsing data";
        findings_.push_back(finding);
    }
}

RiskLevel ExtensionScanner::AssessPermissions(const std::vector<std::string>& permissions) {
    int score = 0;
    
    for (const auto& perm : permissions) {
        if (perm == "<all_urls>" || perm == "webRequestBlocking" || perm == "proxy") {
            score += 3;
        } else if (perm == "webRequest" || perm == "cookies") {
            score += 2;
        } else {
            score += 1;
        }
    }
    
    if (score >= 6) return RiskLevel::High;
    if (score >= 4) return RiskLevel::Medium;
    if (score >= 2) return RiskLevel::Low;
    return RiskLevel::Informational;
}

void ExtensionScanner::ScanExtensionOnBrowserStart(const std::string& extension_path, const std::string& ext_id) {
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((extension_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    std::string manifest_path;
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != "..") {
                std::string test_manifest = extension_path + "\\" + dir_name + "\\manifest.json";
                WIN32_FIND_DATAA manifest_find;
                HANDLE hManifest = FindFirstFileA(test_manifest.c_str(), &manifest_find);
                if (hManifest != INVALID_HANDLE_VALUE) {
                    FindClose(hManifest);
                    manifest_path = test_manifest;
                    break;
                }
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
    
    if (manifest_path.empty()) {
        return;
    }
    
    ExtensionMonitoringProfile profile = ParseManifest(manifest_path, ext_id);
    profile.extension_path = extension_path;
    profile.first_seen = std::chrono::system_clock::now();
    profile.last_scan = profile.first_seen;
    profile.initialization_complete = false;
    profile.staged_files_detected = false;
    
    profile.risk_score = CalculateRiskScore(profile);
    
    if (profile.risk_level >= RiskLevel::Medium) {
        profile.poll_interval_ms = 200;
        profile.deep_monitoring_active = true;
    } else if (profile.risk_level == RiskLevel::Low) {
        profile.poll_interval_ms = 1000;
        profile.deep_monitoring_active = false;
    } else {
        profile.poll_interval_ms = 2000;
        profile.deep_monitoring_active = false;
    }
    
    monitored_extensions_[ext_id] = profile;
    
    CheckStagedFiles(ext_id, extension_path);
    AnalyzeManifest(manifest_path, ext_id);
}

ExtensionMonitoringProfile ExtensionScanner::ParseManifest(const std::string& manifest_path, const std::string& ext_id) {
    ExtensionMonitoringProfile profile;
    profile.extension_id = ext_id;
    profile.risk_level = RiskLevel::Informational;
    
    std::ifstream file(manifest_path);
    if (!file.is_open()) {
        return profile;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    size_t name_pos = content.find("\"name\"");
    if (name_pos != std::string::npos) {
        size_t start = content.find(":", name_pos) + 1;
        size_t quote1 = content.find("\"", start);
        size_t quote2 = content.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            profile.extension_name = content.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }
    
    size_t version_pos = content.find("\"version\"");
    if (version_pos != std::string::npos) {
        size_t start = content.find(":", version_pos) + 1;
        size_t quote1 = content.find("\"", start);
        size_t quote2 = content.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            profile.version = content.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }
    
    size_t perms_pos = content.find("\"permissions\"");
    if (perms_pos != std::string::npos) {
        size_t array_start = content.find("[", perms_pos);
        size_t array_end = content.find("]", array_start);
        if (array_start != std::string::npos && array_end != std::string::npos) {
            std::string perms_str = content.substr(array_start + 1, array_end - array_start - 1);
            size_t pos = 0;
            while ((pos = perms_str.find("\"")) != std::string::npos) {
                size_t end = perms_str.find("\"", pos + 1);
                if (end != std::string::npos) {
                    std::string perm = perms_str.substr(pos + 1, end - pos - 1);
                    profile.permissions.push_back(perm);
                    perms_str = perms_str.substr(end + 1);
                } else {
                    break;
                }
            }
        }
    }
    
    profile.risk_level = AssessPermissions(profile.permissions);
    
    return profile;
}

int ExtensionScanner::CalculateRiskScore(const ExtensionMonitoringProfile& profile) {
    int score = 0;
    
    for (const auto& perm : profile.permissions) {
        if (perm == "webRequestBlocking") score += 30;
        else if (perm == "debugger") score += 25;
        else if (perm == "proxy") score += 20;
        else if (perm == "<all_urls>") score += 15;
        else if (perm == "webRequest") score += 10;
        else if (perm == "cookies") score += 10;
        else if (perm == "storage") score += 5;
        else score += 1;
    }
    
    if (!profile.background_scripts.empty()) score += 5;
    if (profile.background_scripts.size() > 3) score += 10;
    
    return score;
}

void ExtensionScanner::CheckStagedFiles(const std::string& ext_id, const std::string& ext_path) {
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((ext_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    bool suspicious_files = false;
    do {
        std::string filename = find_data.cFileName;
        std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
        
        if (filename.find(".exe") != std::string::npos ||
            filename.find(".dll") != std::string::npos ||
            filename.find(".bat") != std::string::npos ||
            filename.find(".ps1") != std::string::npos) {
            suspicious_files = true;
            std::cout << "[ExtensionScanner] WARNING: Suspicious file in extension " << ext_id << ": " << filename << std::endl;
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
    
    if (suspicious_files) {
        auto it = monitored_extensions_.find(ext_id);
        if (it != monitored_extensions_.end()) {
            it->second.staged_files_detected = true;
            it->second.risk_score += 50;
            it->second.deep_monitoring_active = true;
        }
    }
}

void ExtensionScanner::MonitorInitializationActivity(const std::string& ext_id) {
    auto it = monitored_extensions_.find(ext_id);
    if (it == monitored_extensions_.end()) {
        return;
    }
    
    if (it->second.initialization_complete) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_seen).count();
    
    if (elapsed > 10) {
        it->second.initialization_complete = true;
        return;
    }
    
    CheckStagedFiles(ext_id, it->second.extension_path);
}

void ExtensionScanner::StartActivityMonitoring() {
    if (!is_active_ || !user_consent_ || activity_monitoring_active_) {
        return;
    }

    watcher_running_ = true;
    
    for (const auto& pair : monitored_extensions_) {
        StartWatchersForProfile(pair.second);
    }
    
    activity_monitoring_active_ = true;
    std::cout << "[ExtensionScanner] Activity monitoring started for " << monitored_extensions_.size() << " extensions" << std::endl;
}

void ExtensionScanner::StopActivityMonitoring() {
    if (!activity_monitoring_active_) {
        return;
    }

    watcher_running_ = false;
    
    for (auto& pair : extension_watcher_threads_) {
        if (pair.second) {
            WaitForSingleObject(pair.second, 1000);
            CloseHandle(pair.second);
        }
    }
    
    extension_watcher_threads_.clear();
    watched_extension_paths_.clear();
    activity_monitoring_active_ = false;
}

void ExtensionScanner::UpdateActivityMonitoring() {
    if (!activity_monitoring_active_) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    
    for (auto& pair : monitored_extensions_) {
        MonitorExtensionActivity(pair.second);
    }
}

void ExtensionScanner::MonitorExtensionActivity(const ExtensionMonitoringProfile& profile) {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - profile.last_scan).count();
    
    if (elapsed < profile.poll_interval_ms) {
        return;
    }
    
    std::string manifest_path = profile.extension_path;
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((manifest_path + "\\*").c_str(), &find_data);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
    }
}

void ExtensionScanner::StartWatchersForProfile(const ExtensionMonitoringProfile& profile) {
    if (watched_extension_paths_.find(profile.extension_path) != watched_extension_paths_.end()) {
        return;
    }
    
    watched_extension_paths_.insert(profile.extension_path);

    // Spawn a watcher thread per extension id.
    WatcherParam* param = new WatcherParam();
    param->scanner = this;
    param->extension_id = profile.extension_id;
    param->extension_name = profile.extension_name;
    param->watch_path = profile.extension_path;

    HANDLE hThread = CreateThread(NULL, 0, ExtensionWatcherThread, param, 0, NULL);
    if (hThread) {
        extension_watcher_threads_[profile.extension_id] = hThread;
    } else {
        delete param;
    }
}

void ExtensionScanner::StopWatchersForProfile(const std::string& extension_id) {
    auto it = extension_watcher_threads_.find(extension_id);
    if (it != extension_watcher_threads_.end()) {
        if (it->second) {
            WaitForSingleObject(it->second, 1000);
            CloseHandle(it->second);
        }
        extension_watcher_threads_.erase(it);
    }
}

DWORD WINAPI ExtensionScanner::ExtensionWatcherThread(LPVOID param) {
    WatcherParam* p = reinterpret_cast<WatcherParam*>(param);
    if (!p || !p->scanner) {
        delete p;
        return 1;
    }

    ExtensionScanner* scanner = p->scanner;
    const std::string ext_id = p->extension_id;
    const std::string ext_name = p->extension_name;
    const std::string watch_path = p->watch_path;
    delete p;

    std::wstring wpath(watch_path.begin(), watch_path.end());
    HANDLE hDir = CreateFileW(
        wpath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        return 1;
    }

    std::vector<BYTE> buffer(64 * 1024);
    DWORD bytesReturned = 0;

    while (scanner->watcher_running_) {
        BOOL ok = ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_CREATION,
            &bytesReturned,
            NULL,
            NULL);

        if (!ok) {
            Sleep(250);
            continue;
        }

        if (bytesReturned == 0) {
            Sleep(50);
            continue;
        }

        FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());
        while (true) {
            std::wstring wname(info->FileName, info->FileNameLength / sizeof(WCHAR));
            std::string name(wname.begin(), wname.end());
            std::string full = watch_path + "\\" + name;

            std::string change;
            switch (info->Action) {
                case FILE_ACTION_ADDED: change = "added"; break;
                case FILE_ACTION_REMOVED: change = "removed"; break;
                case FILE_ACTION_MODIFIED: change = "modified"; break;
                case FILE_ACTION_RENAMED_OLD_NAME: change = "renamed_old"; break;
                case FILE_ACTION_RENAMED_NEW_NAME: change = "renamed_new"; break;
                default: change = "unknown"; break;
            }

            // Record activity.
            scanner->RecordActivityEvent(ext_id, ext_name, full, change);

            if (info->NextEntryOffset == 0) {
                break;
            }
            info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<BYTE*>(info) + info->NextEntryOffset);
        }

        Sleep(10);
    }

    CloseHandle(hDir);
    return 0;
}

std::vector<ExtensionActivityEvent> ExtensionScanner::GetRecentActivity(int max_count) {
    if (activity_events_.size() <= static_cast<size_t>(max_count)) {
        return activity_events_;
    }
    return std::vector<ExtensionActivityEvent>(activity_events_.end() - max_count, activity_events_.end());
}

}
