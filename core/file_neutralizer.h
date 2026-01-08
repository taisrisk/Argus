#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>

namespace argus {

class FileNeutralizer {
public:
    static void NeutralizeFile(const std::string& filepath);
    static void NeutralizeFileWithMarker(const std::string& filepath, const std::string& event_id);
    static void ScanAndNeutralizeDirectory(const std::string& directory, const std::string& event_id = "");
    static void ScanAndNeutralizeProcessFiles(uint32_t pid, const std::string& process_path, const std::string& event_id = "");
    static void ContinuousScanAndNeutralize(uint32_t pid, const std::string& process_path, const std::string& event_id, int duration_ms = 3000);
    static void DeepScanAndNeutralize(uint32_t pid, const std::string& process_path, const std::string& event_id);
    
private:
    static std::vector<std::string> FindSQLiteFiles(const std::string& directory);
    static std::vector<std::string> FindSQLiteFilesRecursive(const std::string& directory, int max_depth = 2);
    static void AppendForensicMarker(const std::string& filepath, const std::string& event_id);
};

}

