#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>

namespace argus {

struct PreventionEvent {
    std::string event_id;
    std::chrono::system_clock::time_point timestamp;
    uint32_t pid;
    std::string process_path;
    std::string technique;
    std::vector<std::string> files_accessed;
    std::vector<std::string> files_neutralized;
    bool data_exfiltrated;
    std::string verification_hash;
};

class PreventionLogger {
public:
    static void Initialize();
    static std::string LogPrevention(
        uint32_t pid,
        const std::string& process_path,
        const std::string& technique,
        const std::vector<std::string>& files_accessed,
        const std::vector<std::string>& files_neutralized
    );
    static void DisplayPreventionCertificate(const std::string& event_id);
    
private:
    static std::string GenerateEventID();
    static std::string ComputeVerificationHash(const PreventionEvent& event);
    static void WriteForensicLog(const PreventionEvent& event);
    static std::string GetForensicLogPath();
};

}
