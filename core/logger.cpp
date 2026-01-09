#include "logger.h"
#include <iomanip>
#include <sstream>
#include <ctime>
#include <windows.h>

namespace argus {

Logger::Logger() 
    : is_active_(false) {
}

Logger::~Logger() {
    if (is_active_) {
        Shutdown();
    }
}

bool Logger::Initialize(const std::string& session_id) {
    if (is_active_) {
        return false;
    }
    
    CreateDirectoryA("logs", NULL);
    
    log_file_path_ = "logs\\" + session_id + ".log";
    log_file_.open(log_file_path_, std::ios::out | std::ios::trunc);
    
    if (!log_file_.is_open()) {
        return false;
    }
    
    is_active_ = true;
    LogSessionStart(session_id);
    
    return true;
}

void Logger::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    LogSessionEnd();
    
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    is_active_ = false;
}

void Logger::Log(LogLevel level, const std::string& message) {
    if (!is_active_ || !log_file_.is_open()) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    std::string timestamp = FormatTimestamp(now);
    std::string level_str = LevelToString(level);
    
    log_file_ << "[" << timestamp << "] [" << level_str << "] " << message << std::endl;
    log_file_.flush();
}

void Logger::LogSessionStart(const std::string& session_id) {
    log_file_ << "========================================" << std::endl;
    log_file_ << "ARGUS SESSION START" << std::endl;
    log_file_ << "Session ID: " << session_id << std::endl;
    log_file_ << "========================================" << std::endl;
    log_file_.flush();
}

void Logger::LogSessionEnd() {
    log_file_ << "========================================" << std::endl;
    log_file_ << "ARGUS SESSION END" << std::endl;
    log_file_ << "========================================" << std::endl;
    log_file_.flush();
}

std::string Logger::FormatTimestamp(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()) % 1000;
    
    std::tm tm_buf;
    localtime_s(&tm_buf, &time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    return oss.str();
}

std::string Logger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error: return "ERROR";
        default: return "UNKNOWN";
    }
}

}
