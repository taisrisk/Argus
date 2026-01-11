#pragma once

#include "handle_monitor.h"
#include "file_identity.h"
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <chrono>

namespace argus {

// Forward declarations
class HandleMonitor;
class FileIdentityTracker;

enum class SignalType {
    HandleOpen,
    MemoryRead,
    FileAccess,
    TempStaging,
    NetworkActivity,
    DPAPIAccess,
    EncryptionKeyAccess
};

struct Signal {
    SignalType type;
    std::chrono::system_clock::time_point timestamp;
    uint32_t pid;
    int weight;
    std::string context;
    bool is_corroborated;
};

struct CorrelatedThreat {
    uint32_t pid;
    std::string process_path;
    std::vector<Signal> signals;
    int total_score;
    int corroboration_count;
    bool is_multi_signal;
    bool requires_suspension;
    bool requires_termination;
    std::chrono::system_clock::time_point first_signal;
    std::chrono::system_clock::time_point last_signal;
    std::string classification;
};

class SignalCorrelator {
public:
    SignalCorrelator();
    ~SignalCorrelator();
    
    bool Initialize();
    void Shutdown();
    
    // Register signal sources
    void SetHandleMonitor(HandleMonitor* monitor);
    void SetFileIdentityTracker(FileIdentityTracker* tracker);
    
    // Signal recording
    void RecordSignal(SignalType type, uint32_t pid, int weight, const std::string& context);
    
    // Correlation analysis
    CorrelatedThreat* AnalyzeProcess(uint32_t pid);
    std::vector<CorrelatedThreat> GetCorrelatedThreats(int min_score = 50);
    
    // Decision logic
    bool ShouldSuspend(uint32_t pid);
    bool ShouldTerminate(uint32_t pid);
    std::string ClassifyThreat(uint32_t pid);
    
    // Cleanup
    void CleanupOldSignals(int max_age_seconds = 300);
    
private:
    bool is_active_;
    HandleMonitor* handle_monitor_;
    FileIdentityTracker* file_tracker_;
    
    std::map<uint32_t, CorrelatedThreat> threats_;
    std::chrono::system_clock::time_point last_cleanup_;
    
    int CalculateCorrelationScore(uint32_t pid);
    int CountCorroboratingSignals(uint32_t pid);
    bool AreSignalsCorrelated(const Signal& s1, const Signal& s2);
    void UpdateThreatClassification(CorrelatedThreat& threat);
};

}
