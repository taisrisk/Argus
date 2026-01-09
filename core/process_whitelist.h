#pragma once

#include <string>
#include <vector>
#include <set>
#include <map>

namespace argus {

class ProcessWhitelist {
public:
    ProcessWhitelist();
    ~ProcessWhitelist();
    
    bool LoadFromFile(const std::string& config_path);
    bool IsWhitelisted(const std::string& process_path) const;
    
    std::vector<std::string> GetAllProcesses() const;
    std::vector<std::string> GetCategory(const std::string& category) const;
    
private:
    bool LoadDefault();
    void AddProcess(const std::string& process_name);
    
    std::set<std::string> whitelist_;
    std::map<std::string, std::vector<std::string>> categories_;
    bool is_loaded_;
};

}
