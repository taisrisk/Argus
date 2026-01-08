#pragma once

#include "extension_scanner.h"
#include "network_monitor.h"
#include "file_monitor.h"
#include "process_monitor.h"
#include "credential_monitor.h"
#include <string>
#include <vector>
#include <map>

namespace argus {

struct RiskAssessment {
    RiskLevel level;
    std::string category;
    std::string explanation;
    std::vector<std::string> contributing_signals;
    std::chrono::system_clock::time_point timestamp;
};

class RiskEngine {
public:
    RiskEngine();
    ~RiskEngine();
    
    bool Initialize();
    void Shutdown();
    
    void AnalyzeExtensionFindings(const std::vector<ExtensionFinding>& findings);
    void AnalyzeNetworkEvents(const std::vector<NetworkEvent>& events);
    void AnalyzeFileEvents(const std::vector<FileAccessEvent>& events);
    void AnalyzeProcessEvents(const std::vector<ProcessEvent>& events);
    void AnalyzeCredentialThreats(const std::vector<ThreatChain>& threats);
    
    std::vector<RiskAssessment> GetAssessments();
    void ClearOldAssessments();
    
private:
    void CorrelateSignals();
    RiskLevel AggregateRiskLevel(const std::vector<RiskLevel>& levels);
    
    bool is_active_;
    std::vector<RiskAssessment> assessments_;
    std::map<std::string, std::vector<std::string>> signal_groups_;
};

}
