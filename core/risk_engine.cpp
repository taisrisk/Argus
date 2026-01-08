#include "risk_engine.h"
#include <algorithm>

namespace argus {

RiskEngine::RiskEngine() 
    : is_active_(false) {
}

RiskEngine::~RiskEngine() {
    if (is_active_) {
        Shutdown();
    }
}

bool RiskEngine::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    return true;
}

void RiskEngine::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    assessments_.clear();
    signal_groups_.clear();
}

void RiskEngine::AnalyzeExtensionFindings(const std::vector<ExtensionFinding>& findings) {
    if (!is_active_) {
        return;
    }
    
    for (const auto& finding : findings) {
        RiskAssessment assessment;
        assessment.level = finding.risk_level;
        assessment.category = "Extension";
        assessment.explanation = finding.explanation;
        assessment.contributing_signals.push_back(finding.pattern_matched);
        assessment.timestamp = finding.timestamp;
        
        assessments_.push_back(assessment);
    }
}

void RiskEngine::AnalyzeNetworkEvents(const std::vector<NetworkEvent>& events) {
    if (!is_active_) {
        return;
    }
    
    int suspicious_count = 0;
    std::vector<std::string> signals;
    
    for (const auto& event : events) {
        if (event.is_suspicious) {
            suspicious_count++;
            signals.push_back(event.context + " to " + event.remote_address);
        }
    }
    
    if (suspicious_count > 0) {
        RiskAssessment assessment;
        assessment.category = "Network";
        assessment.contributing_signals = signals;
        assessment.timestamp = std::chrono::system_clock::now();
        
        if (suspicious_count >= 5) {
            assessment.level = RiskLevel::High;
            assessment.explanation = "Multiple suspicious network connections detected";
        } else if (suspicious_count >= 2) {
            assessment.level = RiskLevel::Medium;
            assessment.explanation = "Suspicious network connections detected";
        } else {
            assessment.level = RiskLevel::Low;
            assessment.explanation = "Isolated suspicious network connection";
        }
        
        assessments_.push_back(assessment);
    }
}

void RiskEngine::AnalyzeFileEvents(const std::vector<FileAccessEvent>& events) {
    if (!is_active_) {
        return;
    }
    
    int suspicious_count = 0;
    std::vector<std::string> signals;
    
    for (const auto& event : events) {
        if (event.is_suspicious) {
            suspicious_count++;
            signals.push_back(event.context);
        }
    }
    
    if (suspicious_count > 0) {
        RiskAssessment assessment;
        assessment.category = "File Access";
        assessment.level = (suspicious_count > 1) ? RiskLevel::Medium : RiskLevel::Low;
        assessment.explanation = "Non-browser process accessed browser data paths";
        assessment.contributing_signals = signals;
        assessment.timestamp = std::chrono::system_clock::now();
        
        assessments_.push_back(assessment);
    }
}

void RiskEngine::AnalyzeProcessEvents(const std::vector<ProcessEvent>& events) {
    if (!is_active_) {
        return;
    }
}

void RiskEngine::AnalyzeCredentialThreats(const std::vector<ThreatChain>& threats) {
    if (!is_active_) {
        return;
    }
    
    for (const auto& threat : threats) {
        RiskAssessment assessment;
        assessment.category = "Credential Theft";
        assessment.timestamp = std::chrono::system_clock::now();
        
        if (threat.risk_score >= 10) {
            assessment.level = RiskLevel::High;
            assessment.explanation = "Critical: Suspected credential stealer detected";
        } else if (threat.risk_score >= 8) {
            assessment.level = RiskLevel::High;
            assessment.explanation = "High: Suspicious access to multiple credential stores";
        } else if (threat.risk_score >= 5) {
            assessment.level = RiskLevel::Medium;
            assessment.explanation = "Medium: Unusual access to browser credentials";
        } else {
            assessment.level = RiskLevel::Low;
            assessment.explanation = "Low: Non-browser process accessed browser files";
        }
        
        assessment.contributing_signals.push_back("PID: " + std::to_string(threat.pid));
        assessment.contributing_signals.push_back("Process: " + threat.process_path);
        assessment.contributing_signals.push_back("Risk score: " + std::to_string(threat.risk_score));
        
        assessments_.push_back(assessment);
    }
}

std::vector<RiskAssessment> RiskEngine::GetAssessments() {
    return assessments_;
}

void RiskEngine::ClearOldAssessments() {
    const size_t max_assessments = 100;
    if (assessments_.size() > max_assessments) {
        assessments_.erase(assessments_.begin(), assessments_.begin() + (assessments_.size() - max_assessments));
    }
}

void RiskEngine::CorrelateSignals() {
}

RiskLevel RiskEngine::AggregateRiskLevel(const std::vector<RiskLevel>& levels) {
    if (levels.empty()) {
        return RiskLevel::Informational;
    }
    
    int high_count = std::count(levels.begin(), levels.end(), RiskLevel::High);
    int medium_count = std::count(levels.begin(), levels.end(), RiskLevel::Medium);
    
    if (high_count > 0) return RiskLevel::High;
    if (medium_count > 1) return RiskLevel::High;
    if (medium_count > 0) return RiskLevel::Medium;
    
    return RiskLevel::Low;
}

}
