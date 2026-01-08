#include "extension_scanner.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace argus {

ExtensionScanner::ExtensionScanner() 
    : is_active_(false), user_consent_(false) {
}

ExtensionScanner::~ExtensionScanner() {
    if (is_active_) {
        Shutdown();
    }
}

bool ExtensionScanner::Initialize(bool user_consent) {
    if (is_active_) {
        return false;
    }
    
    user_consent_ = user_consent;
    is_active_ = true;
    
    return true;
}

void ExtensionScanner::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    findings_.clear();
}

void ExtensionScanner::ScanExtensions(const std::string& browser_profile_path) {
    if (!is_active_ || !user_consent_) {
        return;
    }
    
    std::string extensions_path = browser_profile_path + "\\Extensions";
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((extensions_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != ".." && dir_name != "Temp") {
                ScanExtensionDirectory(extensions_path + "\\" + dir_name);
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
}

std::vector<ExtensionFinding> ExtensionScanner::GetFindings() {
    return findings_;
}

void ExtensionScanner::ClearFindings() {
    findings_.clear();
}

void ExtensionScanner::ScanExtensionDirectory(const std::string& ext_path) {
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((ext_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    std::string ext_id;
    size_t last_slash = ext_path.find_last_of("\\");
    if (last_slash != std::string::npos) {
        ext_id = ext_path.substr(last_slash + 1);
    }
    
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != "..") {
                std::string manifest_path = ext_path + "\\" + dir_name + "\\manifest.json";
                
                WIN32_FIND_DATAA manifest_find;
                HANDLE hManifest = FindFirstFileA(manifest_path.c_str(), &manifest_find);
                if (hManifest != INVALID_HANDLE_VALUE) {
                    FindClose(hManifest);
                    AnalyzeManifest(manifest_path, ext_id);
                    break;
                }
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
}

void ExtensionScanner::AnalyzeManifest(const std::string& manifest_path, const std::string& ext_id) {
    std::ifstream file(manifest_path);
    if (!file.is_open()) {
        return;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    ExtensionFinding finding;
    finding.extension_id = ext_id;
    finding.file_path = manifest_path;
    finding.timestamp = std::chrono::system_clock::now();
    
    size_t name_pos = content.find("\"name\"");
    if (name_pos != std::string::npos) {
        size_t start = content.find(":", name_pos) + 1;
        size_t quote1 = content.find("\"", start);
        size_t quote2 = content.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            finding.extension_name = content.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }
    
    if (finding.extension_name.empty() || finding.extension_name.find("__MSG_") == 0) {
        return;
    }
    
    std::string lower_name = finding.extension_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("proton vpn") != std::string::npos ||
        lower_name.find("protonvpn") != std::string::npos ||
        lower_name.find("nordvpn") != std::string::npos ||
        lower_name.find("expressvpn") != std::string::npos ||
        lower_name.find("surfshark") != std::string::npos ||
        lower_name.find("mullvad") != std::string::npos ||
        lower_name.find("windscribe") != std::string::npos ||
        lower_name.find("cyberghost") != std::string::npos ||
        lower_name.find("tunnelbear") != std::string::npos ||
        lower_name.find("private internet access") != std::string::npos ||
        lower_name.find("vyprvpn") != std::string::npos) {
        return;
    }
    
    if (lower_name.find("comet") != std::string::npos ||
        lower_name.find("perplexity") != std::string::npos) {
        return;
    }
    
    std::vector<std::string> high_risk_perms = {
        "webRequestBlocking", "debugger", "proxy"
    };
    
    std::vector<std::string> medium_risk_perms = {
        "<all_urls>", "webRequest"
    };
    
    std::vector<std::string> found_high;
    std::vector<std::string> found_medium;
    
    for (const auto& perm : high_risk_perms) {
        if (content.find(perm) != std::string::npos) {
            found_high.push_back(perm);
        }
    }
    
    for (const auto& perm : medium_risk_perms) {
        if (content.find(perm) != std::string::npos) {
            found_medium.push_back(perm);
        }
    }
    
    if (!found_high.empty()) {
        finding.risk_level = RiskLevel::High;
        finding.pattern_matched = "High-risk permissions: ";
        for (size_t i = 0; i < found_high.size(); ++i) {
            finding.pattern_matched += found_high[i];
            if (i < found_high.size() - 1) finding.pattern_matched += ", ";
        }
        finding.explanation = "Extension can intercept/modify all web traffic";
        findings_.push_back(finding);
    } else if (found_medium.size() >= 2) {
        finding.risk_level = RiskLevel::Medium;
        finding.pattern_matched = "Broad permissions: ";
        for (size_t i = 0; i < found_medium.size(); ++i) {
            finding.pattern_matched += found_medium[i];
            if (i < found_medium.size() - 1) finding.pattern_matched += ", ";
        }
        finding.explanation = "Extension has broad access to browsing data";
        findings_.push_back(finding);
    }
}

RiskLevel ExtensionScanner::AssessPermissions(const std::vector<std::string>& permissions) {
    int score = 0;
    
    for (const auto& perm : permissions) {
        if (perm == "<all_urls>" || perm == "webRequestBlocking" || perm == "proxy") {
            score += 3;
        } else if (perm == "webRequest" || perm == "cookies") {
            score += 2;
        } else {
            score += 1;
        }
    }
    
    if (score >= 6) return RiskLevel::High;
    if (score >= 4) return RiskLevel::Medium;
    if (score >= 2) return RiskLevel::Low;
    return RiskLevel::Informational;
}

}
