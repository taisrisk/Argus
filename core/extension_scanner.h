#pragma once

#include <string>
#include <vector>
#include <chrono>

namespace argus {

enum class RiskLevel {
    Informational,
    Low,
    Medium,
    High
};

struct ExtensionFinding {
    std::string extension_id;
    std::string extension_name;
    std::string file_path;
    std::string pattern_matched;
    RiskLevel risk_level;
    std::string explanation;
    std::chrono::system_clock::time_point timestamp;
};

class ExtensionScanner {
public:
    ExtensionScanner();
    ~ExtensionScanner();
    
    bool Initialize(bool user_consent);
    void Shutdown();
    
    void ScanExtensions(const std::string& browser_profile_path);
    std::vector<ExtensionFinding> GetFindings();
    void ClearFindings();
    
    bool HasUserConsent() const { return user_consent_; }
    
private:
    void ScanExtensionDirectory(const std::string& ext_path);
    void AnalyzeManifest(const std::string& manifest_path, const std::string& ext_id);
    RiskLevel AssessPermissions(const std::vector<std::string>& permissions);
    
    bool is_active_;
    bool user_consent_;
    std::vector<ExtensionFinding> findings_;
};

}
