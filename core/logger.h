#pragma once

#include <string>
#include <fstream>
#include <chrono>

namespace argus {

enum class LogLevel {
    Info,
    Warning,
    Error
};

class Logger {
public:
    Logger();
    ~Logger();
    
    bool Initialize(const std::string& session_id);
    void Shutdown();
    
    void Log(LogLevel level, const std::string& message);
    void LogSessionStart(const std::string& session_id);
    void LogSessionEnd();
    
private:
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& time);
    std::string LevelToString(LogLevel level);
    
    bool is_active_;
    std::string log_file_path_;
    std::ofstream log_file_;
};

}
