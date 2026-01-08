#include "session_manager.h"
#include <sstream>
#include <iomanip>
#include <random>

namespace argus {

SessionManager::SessionManager() 
    : is_active_(false) {
}

SessionManager::~SessionManager() {
    if (is_active_) {
        Shutdown();
    }
}

bool SessionManager::Initialize() {
    if (is_active_) {
        return false;
    }
    
    session_id_ = GenerateSessionId();
    start_time_ = std::chrono::system_clock::now();
    is_active_ = true;
    
    return true;
}

void SessionManager::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    ExecuteCleanup();
    
    is_active_ = false;
    session_id_.clear();
    cleanup_callbacks_.clear();
}

void SessionManager::RegisterCleanupCallback(std::function<void()> callback) {
    cleanup_callbacks_.push_back(callback);
}

std::string SessionManager::GenerateSessionId() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "argus_" << timestamp << "_";
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    
    return ss.str();
}

void SessionManager::ExecuteCleanup() {
    for (auto it = cleanup_callbacks_.rbegin(); it != cleanup_callbacks_.rend(); ++it) {
        (*it)();
    }
}

}
