#pragma once

#include "credential_monitor.h"
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace argus {

// Forward declarations
class FileIdentityTracker;
class CredentialMonitor;

class ThreatDetector {
public:
    ThreatDetector(CredentialMonitor* monitor);
    ~ThreatDetector();
    
    void RecordAccess(uint32_t pid, const std::wstring& filepath);
    void AnalyzeAccessPatterns();
    int CalculateRiskScore(const ThreatChain& chain);
    
    bool IsSensitiveFile(const std::wstring& filepath);
    AssetType GetAssetType(const std::wstring& filepath);
    
private:
    CredentialMonitor* monitor_;
    
    void HandleLoginDataAccess(uint32_t pid, const std::string& filepath, AccessEvent& event);
    void HandleLocalStateAccess(uint32_t pid, const std::string& filepath, AccessEvent& event);
    void HandleCookieAccess(uint32_t pid, const std::string& filepath, AccessEvent& event, int risk_score);
    void HandleHighRiskThreshold(uint32_t pid, int risk_score);
};

}
