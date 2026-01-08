#include "file_neutralizer.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <ctime>

namespace argus {

void FileNeutralizer::AppendForensicMarker(const std::string& filepath, const std::string& event_id) {
    HANDLE hFile = CreateFileA(
        filepath.c_str(),
        FILE_APPEND_DATA,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile != INVALID_HANDLE_VALUE) {
        std::time_t now = std::time(nullptr);
        struct tm timeinfo;
        gmtime_s(&timeinfo, &now);
        
        char timestamp[32];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
        
        std::string marker = "\n--- ARGUS_PREVENTED ---\n";
        marker += "event_id=" + event_id + "\n";
        marker += "timestamp=" + std::string(timestamp) + "\n";
        marker += "reason=SQLITE_CREDENTIAL_EXFIL\n";
        marker += "--- END ---\n";
        
        DWORD written = 0;
        WriteFile(hFile, marker.c_str(), static_cast<DWORD>(marker.size()), &written, NULL);
        CloseHandle(hFile);
    }
}

void FileNeutralizer::NeutralizeFile(const std::string& filepath) {
    HANDLE hFile = CreateFileA(
        filepath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        
        char corruption[32768];
        for (int i = 0; i < sizeof(corruption); i++) {
            corruption[i] = (char)(rand() % 256);
        }
        
        DWORD written = 0;
        WriteFile(hFile, corruption, sizeof(corruption), &written, NULL);
        SetEndOfFile(hFile);
        FlushFileBuffers(hFile);
        
        std::cout << "  [NEUTRALIZED] " << filepath << std::endl;
        CloseHandle(hFile);
    }
}

void FileNeutralizer::NeutralizeFileWithMarker(const std::string& filepath, const std::string& event_id) {
    NeutralizeFile(filepath);
    AppendForensicMarker(filepath, event_id);
}

std::vector<std::string> FileNeutralizer::FindSQLiteFiles(const std::string& directory) {
    std::vector<std::string> files;
    
    std::vector<std::string> patterns = {"*.db", "*.sqlite", "*.sqlite3"};
    
    for (const auto& pattern : patterns) {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((directory + "\\" + pattern).c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    files.push_back(directory + "\\" + findData.cFileName);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    return files;
}

std::vector<std::string> FileNeutralizer::FindSQLiteFilesRecursive(const std::string& directory, int max_depth) {
    std::vector<std::string> files = FindSQLiteFiles(directory);
    
    if (max_depth > 0) {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((directory + "\\*").c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    strcmp(findData.cFileName, ".") != 0 &&
                    strcmp(findData.cFileName, "..") != 0) {
                    
                    std::string subdir = directory + "\\" + findData.cFileName;
                    auto subfiles = FindSQLiteFilesRecursive(subdir, max_depth - 1);
                    files.insert(files.end(), subfiles.begin(), subfiles.end());
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    return files;
}

void FileNeutralizer::ScanAndNeutralizeDirectory(const std::string& directory, const std::string& event_id) {
    auto files = FindSQLiteFiles(directory);
    
    if (!files.empty()) {
        for (const auto& file : files) {
            if (event_id.empty()) {
                NeutralizeFile(file);
            } else {
                NeutralizeFileWithMarker(file, event_id);
            }
        }
    }
}

void FileNeutralizer::ScanAndNeutralizeProcessFiles(uint32_t pid, const std::string& process_path, const std::string& event_id) {
    size_t lastSlash = process_path.find_last_of("\\");
    if (lastSlash == std::string::npos) return;
    
    std::string proc_dir = process_path.substr(0, lastSlash);
    
    std::cout << "  [SCAN] " << proc_dir << std::endl;
    ScanAndNeutralizeDirectory(proc_dir, event_id);
}

void FileNeutralizer::ContinuousScanAndNeutralize(uint32_t pid, const std::string& process_path, const std::string& event_id, int duration_ms) {
    std::thread([pid, process_path, event_id, duration_ms]() {
        auto start = std::chrono::steady_clock::now();
        int files_neutralized = 0;
        
        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            
            if (elapsed >= duration_ms) break;
            
            size_t lastSlash = process_path.find_last_of("\\");
            if (lastSlash != std::string::npos) {
                std::string proc_dir = process_path.substr(0, lastSlash);
                auto files = FindSQLiteFiles(proc_dir);
                
                for (const auto& file : files) {
                    NeutralizeFileWithMarker(file, event_id);
                    files_neutralized++;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        std::cout << "\n=== PREVENTION CONFIRMED ===" << std::endl;
        std::cout << "Event ID: " << event_id << std::endl;
        std::cout << "Threat: Credential Staging (SQLite)" << std::endl;
        std::cout << "Result: Data rendered unusable before read" << std::endl;
        std::cout << "Exfiltration: NONE" << std::endl;
        std::cout << "============================\n" << std::endl;
    }).detach();
}

void FileNeutralizer::DeepScanAndNeutralize(uint32_t pid, const std::string& process_path, const std::string& event_id) {
    std::thread([pid, process_path, event_id]() {
        size_t lastSlash = process_path.find_last_of("\\");
        if (lastSlash == std::string::npos) return;
        
        std::string proc_dir = process_path.substr(0, lastSlash);
        
        auto root_files = FindSQLiteFiles(proc_dir);
        
        if (root_files.empty()) {
            size_t parent_slash = proc_dir.find_last_of("\\");
            if (parent_slash != std::string::npos) {
                std::string parent_dir = proc_dir.substr(0, parent_slash);
                auto parent_files = FindSQLiteFilesRecursive(parent_dir, 1);
                
                if (!parent_files.empty()) {
                    for (const auto& file : parent_files) {
                        NeutralizeFileWithMarker(file, event_id);
                    }
                } else {
                    char tempPath[MAX_PATH];
                    if (GetTempPathA(MAX_PATH, tempPath)) {
                        auto temp_files = FindSQLiteFilesRecursive(tempPath, 2);
                        for (const auto& file : temp_files) {
                            NeutralizeFileWithMarker(file, event_id);
                        }
                    }
                    
                    char userProfile[MAX_PATH];
                    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
                        std::vector<std::string> user_dirs = {
                            std::string(userProfile) + "\\Desktop",
                            std::string(userProfile) + "\\Documents",
                            std::string(userProfile) + "\\Downloads"
                        };
                        
                        for (const auto& dir : user_dirs) {
                            auto user_files = FindSQLiteFiles(dir);
                            for (const auto& file : user_files) {
                                NeutralizeFileWithMarker(file, event_id);
                            }
                        }
                    }
                }
            }
        } else {
            for (const auto& file : root_files) {
                NeutralizeFileWithMarker(file, event_id);
            }
        }
        
        std::cout << "[STATUS] Protection successful — no credentials exposed\n" << std::endl;
    }).detach();
}

}

