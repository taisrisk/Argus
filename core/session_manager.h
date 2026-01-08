#pragma once

#include <string>
#include <chrono>
#include <memory>
#include <functional>
#include <vector>

namespace argus {

class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    bool Initialize();
    void Shutdown();
    
    std::string GetSessionId() const { return session_id_; }
    std::chrono::system_clock::time_point GetStartTime() const { return start_time_; }
    bool IsActive() const { return is_active_; }
    
    void RegisterCleanupCallback(std::function<void()> callback);
    
private:
    std::string GenerateSessionId();
    void ExecuteCleanup();
    
    std::string session_id_;
    std::chrono::system_clock::time_point start_time_;
    bool is_active_;
    std::vector<std::function<void()>> cleanup_callbacks_;
};

}
