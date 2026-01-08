#pragma once

#include <string>
#include <vector>
#include <windows.h>

namespace argus {

class FileNeutralizer {
public:
    static void NeutralizeFile(const std::string& filepath);
    static void ScanAndNeutralizeDirectory(const std::string& directory);
    static void ScanAndNeutralizeProcessFiles(uint32_t pid, const std::string& process_path);
    static void DelayedScanAndNeutralize(uint32_t pid, const std::string& process_path, int delay_ms = 2000);
    
private:
    static std::vector<std::string> FindSQLiteFiles(const std::string& directory);
};

}
