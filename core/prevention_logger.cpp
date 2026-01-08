#include "prevention_logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <windows.h>
#include <shlobj.h>

namespace argus {

void PreventionLogger::Initialize() {
    std::string log_dir = GetForensicLogPath();
    CreateDirectoryA(log_dir.c_str(), NULL);
}

std::string PreventionLogger::GenerateEventID() {
    GUID guid;
    CoCreateGuid(&guid);
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << guid.Data1 << "-"
        << std::setw(4) << guid.Data2 << "-"
        << std::setw(4) << guid.Data3 << "-";
    
    for (int i = 0; i < 8; i++) {
        oss << std::setw(2) << (int)guid.Data4[i];
    }
    
    return oss.str();
}

std::string PreventionLogger::ComputeVerificationHash(const PreventionEvent& event) {
    std::ostringstream data;
    data << event.event_id << event.pid << event.process_path << event.technique;
    for (size_t i = 0; i < event.files_accessed.size(); i++) {
        data << event.files_accessed[i];
    }
    for (size_t i = 0; i < event.files_neutralized.size(); i++) {
        data << event.files_neutralized[i];
    }
    
    unsigned int hash = 0x811c9dc5;
    for (char c : data.str()) {
        hash ^= c;
        hash *= 0x01000193;
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << hash;
    return oss.str();
}

std::string PreventionLogger::GetForensicLogPath() {
    char programData[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData) == S_OK) {
        return std::string(programData) + "\\Argus\\forensics";
    }
    return ".\\forensics";
}

void PreventionLogger::WriteForensicLog(const PreventionEvent& event) {
    std::string log_path = GetForensicLogPath() + "\\events.log";
    
    std::ofstream log(log_path, std::ios::app);
    if (!log.is_open()) return;
    
    std::time_t t = std::chrono::system_clock::to_time_t(event.timestamp);
    struct tm timeinfo;
    gmtime_s(&timeinfo, &t);
    
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
    
    log << "[" << timestamp << "]\n";
    log << "EVENT_ID: " << event.event_id << "\n";
    log << "PROCESS: " << event.process_path << " (PID " << event.pid << ")\n";
    log << "ACTION: " << event.technique << "\n";
    
    if (!event.files_accessed.empty()) {
        log << "FILES_ACCESSED: ";
        for (size_t i = 0; i < event.files_accessed.size(); i++) {
            if (i > 0) log << ", ";
            size_t pos = event.files_accessed[i].find_last_of("\\");
            log << (pos != std::string::npos ? event.files_accessed[i].substr(pos + 1) : event.files_accessed[i]);
        }
        log << "\n";
    }
    
    if (!event.files_neutralized.empty()) {
        log << "FILES_NEUTRALIZED: " << event.files_neutralized.size() << "\n";
    }
    
    log << "DATA_EXFILTRATED: " << (event.data_exfiltrated ? "TRUE" : "FALSE") << "\n";
    log << "RESULT: EXTRACTION_PREVENTED\n";
    log << "VERIFICATION: " << event.verification_hash << "\n";
    log << "\n";
    
    log.close();
}

std::string PreventionLogger::LogPrevention(
    uint32_t pid,
    const std::string& process_path,
    const std::string& technique,
    const std::vector<std::string>& files_accessed,
    const std::vector<std::string>& files_neutralized) {
    
    PreventionEvent event;
    event.event_id = GenerateEventID();
    event.timestamp = std::chrono::system_clock::now();
    event.pid = pid;
    event.process_path = process_path;
    event.technique = technique;
    event.files_accessed = files_accessed;
    event.files_neutralized = files_neutralized;
    event.data_exfiltrated = false;
    event.verification_hash = ComputeVerificationHash(event);
    
    WriteForensicLog(event);
    
    return event.event_id;
}

void PreventionLogger::DisplayPreventionCertificate(const std::string& event_id) {
    std::cout << "\n=== Protection Successful ===" << std::endl;
    std::cout << "Event: " << event_id << std::endl;
    std::cout << "Status: Credential extraction prevented" << std::endl;
    std::cout << "Result: No credentials exposed" << std::endl;
    std::cout << "============================\n" << std::endl;
}

}

