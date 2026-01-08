#include "file_neutralizer.h"
#include <iostream>
#include <thread>
#include <chrono>

namespace argus {

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

void FileNeutralizer::ScanAndNeutralizeDirectory(const std::string& directory) {
    auto files = FindSQLiteFiles(directory);
    
    if (!files.empty()) {
        std::cout << "  [SCAN] Found " << files.size() << " SQLite files in " << directory << std::endl;
        for (const auto& file : files) {
            NeutralizeFile(file);
        }
    }
}

void FileNeutralizer::ScanAndNeutralizeProcessFiles(uint32_t pid, const std::string& process_path) {
    size_t lastSlash = process_path.find_last_of("\\");
    if (lastSlash == std::string::npos) return;
    
    std::string proc_dir = process_path.substr(0, lastSlash);
    
    std::cout << "  [SCAN] Checking: " << proc_dir << std::endl;
    ScanAndNeutralizeDirectory(proc_dir);
}

void FileNeutralizer::DelayedScanAndNeutralize(uint32_t pid, const std::string& process_path, int delay_ms) {
    std::thread([pid, process_path, delay_ms]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        
        std::cout << "\n[DELAYED SCAN] PID " << pid << " - checking for staged files..." << std::endl;
        ScanAndNeutralizeProcessFiles(pid, process_path);
        std::cout << "[DELAYED SCAN] Complete\n" << std::endl;
    }).detach();
}

}
