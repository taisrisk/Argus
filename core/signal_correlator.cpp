#include "signal_correlator.h"
#include <algorithm>
#include <iostream>

namespace argus {

SignalCorrelator::SignalCorrelator() 
    : is_active_(false), handle_monitor_(nullptr), file_tracker_(nullptr) {
}

SignalCorrelator::~SignalCorrelator() {
    if (is_active_) {
        Shutdown();
    }
}

bool SignalCorrelator::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    last_cleanup_ = std::chrono::system_clock::now();
    
    std::cout << "[SignalCorrelator] Multi-signal threat correlation active" << std::endl;
    std::cout << "[SignalCorrelator] Rule: Any single signal can fail - only mesh is authoritative" << std::endl;
    
    return true;
}

void SignalCorrelator::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    threats_.clear();
}

void SignalCorrelator::SetHandleMonitor(HandleMonitor* monitor) {
    handle_monitor_ = monitor;
}

void SignalCorrelator::SetFileIdentityTracker(FileIdentityTracker* tracker) {
    file_tracker_ = tracker;
}

void SignalCorrelator::RecordSignal(SignalType type, uint32_t pid, int weight, const std::string& context) {
    if (!is_active_) return;
    
    auto now = std::chrono::system_clock::now();
    
    // Initialize threat if not exists
    if (threats_.find(pid) == threats_.end()) {
        CorrelatedThreat threat;
        threat.pid = pid;
        threat.process_path = ""; // Will be filled by caller
        threat.total_score = 0;
        threat.corroboration_count = 0;
        threat.is_multi_signal = false;
        threat.requires_suspension = false;
        threat.requires_termination = false;
        threat.first_signal = now;
        threat.last_signal = now;
        threat.classification = "Unknown";
        threats_[pid] = threat;
    }
    
    // Create signal
    Signal signal;
    signal.type = type;
    signal.timestamp = now;
    signal.pid = pid;
    signal.weight = weight;
    signal.context = context;
    signal.is_corroborated = false;
    
    threats_[pid].signals.push_back(signal);
    threats_[pid].last_signal = now;
    
    // Update correlation
    threats_[pid].total_score = CalculateCorrelationScore(pid);
    threats_[pid].corroboration_count = CountCorroboratingSignals(pid);
    threats_[pid].is_multi_signal = threats_[pid].signals.size() >= 2;
    
    UpdateThreatClassification(threats_[pid]);
}

bool SignalCorrelator::AreSignalsCorrelated(const Signal& s1, const Signal& s2) {
    // Signals within 5 seconds of each other
    auto later = (s1.timestamp > s2.timestamp) ? s1.timestamp : s2.timestamp;
    auto earlier = (s1.timestamp <= s2.timestamp) ? s1.timestamp : s2.timestamp;
    
    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(later - earlier).count();
    
    if (time_diff > 5) {
        return false;
    }
    
    // Strong correlations
    if (s1.type == SignalType::HandleOpen && s2.type == SignalType::MemoryRead) return true;
    if (s1.type == SignalType::FileAccess && s2.type == SignalType::TempStaging) return true;
    if (s1.type == SignalType::EncryptionKeyAccess && s2.type == SignalType::FileAccess) return true;
    if (s1.type == SignalType::DPAPIAccess && s2.type == SignalType::MemoryRead) return true;
    if (s1.type == SignalType::TempStaging && s2.type == SignalType::NetworkActivity) return true;
    
    return false;
}

int SignalCorrelator::CountCorroboratingSignals(uint32_t pid) {
    auto it = threats_.find(pid);
    if (it == threats_.end()) {
        return 0;
    }
    
    auto& signals = it->second.signals;
    int corroborated = 0;
    
    for (size_t i = 0; i < signals.size(); ++i) {
        for (size_t j = i + 1; j < signals.size(); ++j) {
            if (AreSignalsCorrelated(signals[i], signals[j])) {
                if (!signals[i].is_corroborated) {
                    signals[i].is_corroborated = true;
                    corroborated++;
                }
                if (!signals[j].is_corroborated) {
                    signals[j].is_corroborated = true;
                    corroborated++;
                }
            }
        }
    }
    
    return corroborated;
}

int SignalCorrelator::CalculateCorrelationScore(uint32_t pid) {
    auto it = threats_.find(pid);
    if (it == threats_.end()) {
        return 0;
    }
    
    CorrelatedThreat& threat = it->second;
    int score = 0;
    
    // Base signal scores
    for (const auto& signal : threat.signals) {
        if (signal.is_corroborated) {
            score += signal.weight * 2; // Double weight for corroborated signals
        } else {
            score += signal.weight / 2; // Half weight for standalone signals
        }
    }
    
    // Multi-signal bonus
    if (threat.signals.size() >= 3) {
        score += 25;
    } else if (threat.signals.size() >= 2) {
        score += 10;
    }
    
    // Rapid activity bonus
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        threat.last_signal - threat.first_signal).count();
    
    if (duration < 5 && threat.signals.size() >= 2) {
        score += 20;
    }
    
    // Cross-validate with handle monitor
    if (handle_monitor_) {
        auto* activity = handle_monitor_->GetProcessActivity(pid);
        if (activity) {
            if (activity->targets_browser) {
                score += 15;
            }
            if (activity->suspicious_handle_count > 0) {
                score += 10;
            }
            if (activity->memory_read_count > 3) {
                score += 15;
            }
        }
    }
    
    // Cross-validate with file tracker
    if (file_tracker_) {
        auto* file_activity = file_tracker_->GetProcessActivity(pid);
        if (file_activity) {
            if (file_activity->has_temp_staging) {
                score += 30;
            }
            if (file_activity->behavior_score >= 90) {
                score += 25;
            }
        }
    }
    
    return score;
}

void SignalCorrelator::UpdateThreatClassification(CorrelatedThreat& threat) {
    int score = threat.total_score;
    int signals = threat.signals.size();
    int corroborated = threat.corroboration_count;
    
    // Classification logic
    if (score >= 100 && corroborated >= 2) {
        threat.classification = "CONFIRMED_STEALER";
        threat.requires_termination = true;
        threat.requires_suspension = true;
    } else if (score >= 75 && signals >= 3) {
        threat.classification = "HIGH_CONFIDENCE_THREAT";
        threat.requires_termination = true;
        threat.requires_suspension = true;
    } else if (score >= 50 && corroborated >= 1) {
        threat.classification = "SUSPECTED_THREAT";
        threat.requires_suspension = true;
        threat.requires_termination = false;
    } else if (score >= 30) {
        threat.classification = "SUSPICIOUS_ACTIVITY";
        threat.requires_suspension = false;
        threat.requires_termination = false;
    } else {
        threat.classification = "MONITORING";
        threat.requires_suspension = false;
        threat.requires_termination = false;
    }
}

CorrelatedThreat* SignalCorrelator::AnalyzeProcess(uint32_t pid) {
    auto it = threats_.find(pid);
    if (it != threats_.end()) {
        // Recalculate
        it->second.total_score = CalculateCorrelationScore(pid);
        it->second.corroboration_count = CountCorroboratingSignals(pid);
        UpdateThreatClassification(it->second);
        return &it->second;
    }
    return nullptr;
}

std::vector<CorrelatedThreat> SignalCorrelator::GetCorrelatedThreats(int min_score) {
    std::vector<CorrelatedThreat> result;
    
    for (auto& pair : threats_) {
        if (pair.second.total_score >= min_score) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

bool SignalCorrelator::ShouldSuspend(uint32_t pid) {
    auto* threat = AnalyzeProcess(pid);
    return threat && threat->requires_suspension;
}

bool SignalCorrelator::ShouldTerminate(uint32_t pid) {
    auto* threat = AnalyzeProcess(pid);
    return threat && threat->requires_termination;
}

std::string SignalCorrelator::ClassifyThreat(uint32_t pid) {
    auto* threat = AnalyzeProcess(pid);
    return threat ? threat->classification : "UNKNOWN";
}

void SignalCorrelator::CleanupOldSignals(int max_age_seconds) {
    auto now = std::chrono::system_clock::now();
    
    std::vector<uint32_t> expired_pids;
    for (auto& pair : threats_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.last_signal).count();
        if (age > max_age_seconds) {
            expired_pids.push_back(pair.first);
        }
    }
    
    for (uint32_t pid : expired_pids) {
        threats_.erase(pid);
    }
}

}
