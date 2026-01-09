#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace argus {

class CredentialMonitor;

class MonitoringThreads {
public:
    static DWORD WINAPI WatcherThread(LPVOID param);
    static DWORD WINAPI PollingThread(LPVOID param);
    static DWORD WINAPI TempFileWatcherThread(LPVOID param);
    
private:
    static void ProcessDirectoryChanges(CredentialMonitor* monitor, 
                                       const std::vector<std::wstring>& critical_files);
    static void ProcessTempFileCreation(CredentialMonitor* monitor,
                                       const std::wstring& fullPath);
};

}
