#include "process_whitelist.h"
#include <fstream>
#include <algorithm>
#include <iostream>

namespace argus {

ProcessWhitelist::ProcessWhitelist() : is_loaded_(false) {
}

ProcessWhitelist::~ProcessWhitelist() {
}

bool ProcessWhitelist::LoadFromFile(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cerr << "[ProcessWhitelist] Failed to open: " << config_path << std::endl;
        std::cerr << "[ProcessWhitelist] Loading default whitelist..." << std::endl;
        return LoadDefault();
    }
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    // Simple JSON parsing for processes array
    size_t pos = 0;
    while ((pos = content.find("\"processes\"", pos)) != std::string::npos) {
        size_t array_start = content.find("[", pos);
        size_t array_end = content.find("]", array_start);
        
        if (array_start == std::string::npos || array_end == std::string::npos) {
            break;
        }
        
        std::string array_content = content.substr(array_start + 1, array_end - array_start - 1);
        
        size_t item_pos = 0;
        while ((item_pos = array_content.find("\"", item_pos)) != std::string::npos) {
            size_t end_quote = array_content.find("\"", item_pos + 1);
            if (end_quote == std::string::npos) break;
            
            std::string process_name = array_content.substr(item_pos + 1, end_quote - item_pos - 1);
            if (!process_name.empty() && process_name != "processes") {
                AddProcess(process_name);
            }
            
            item_pos = end_quote + 1;
        }
        
        pos = array_end + 1;
    }
    
    is_loaded_ = !whitelist_.empty();
    
    if (is_loaded_) {
        std::cout << "[ProcessWhitelist] Loaded " << whitelist_.size() << " whitelisted processes" << std::endl;
    } else {
        std::cerr << "[ProcessWhitelist] No processes loaded, using default" << std::endl;
        return LoadDefault();
    }
    
    return true;
}

bool ProcessWhitelist::LoadDefault() {
    // Minimal default whitelist
    const std::vector<std::string> defaults = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "elevation_service.exe", "googleupdate.exe",
        "system32", "\\windows\\", "explorer.exe",
        "argus.exe"
    };
    
    for (const auto& proc : defaults) {
        AddProcess(proc);
    }
    
    is_loaded_ = true;
    std::cout << "[ProcessWhitelist] Loaded default whitelist (" << defaults.size() << " processes)" << std::endl;
    return true;
}

void ProcessWhitelist::AddProcess(const std::string& process_name) {
    std::string lower = process_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    whitelist_.insert(lower);
}

bool ProcessWhitelist::IsWhitelisted(const std::string& process_path) const {
    std::string lower = process_path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& whitelisted : whitelist_) {
        if (lower.find(whitelisted) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> ProcessWhitelist::GetAllProcesses() const {
    return std::vector<std::string>(whitelist_.begin(), whitelist_.end());
}

std::vector<std::string> ProcessWhitelist::GetCategory(const std::string& category) const {
    auto it = categories_.find(category);
    if (it != categories_.end()) {
        return it->second;
    }
    return std::vector<std::string>();
}

}
