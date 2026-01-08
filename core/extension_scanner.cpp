#include "extension_scanner.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <iostream>

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
    
    std::cout << "  Looking for extensions in: " << extensions_path << std::endl;
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((extensions_path + "\\*").c_str(), &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cout << "  Extensions folder not found or inaccessible (error " << err << ")" << std::endl;
        return;
    }
    
    int ext_count = 0;
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string dir_name = find_data.cFileName;
            if (dir_name != "." && dir_name != ".." && dir_name != "Temp") {
                ext_count++;
                std::cout << "  Found extension: " << dir_name << std::endl;
                ScanExtensionDirectory(extensions_path + "\\" + dir_name);
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
    
    std::cout << "  Total extensions found: " << ext_count << std::endl;
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
        finding.extension_name = content.substr(quote1 + 1, quote2 - quote1 - 1);
    }
    
    std::vector<std::string> high_risk_perms = {
        "webRequest", "webRequestBlocking", "proxy", 
        "<all_urls>", "debugger", "cookies"
    };
    
    std::vector<std::string> found_perms;
    for (const auto& perm : high_risk_perms) {
        if (content.find(perm) != std::string::npos) {
            found_perms.push_back(perm);
        }
    }
    
    if (!found_perms.empty()) {
        finding.risk_level = AssessPermissions(found_perms);
        finding.pattern_matched = "High-risk permissions: ";
        for (size_t i = 0; i < found_perms.size(); ++i) {
            finding.pattern_matched += found_perms[i];
            if (i < found_perms.size() - 1) {
                finding.pattern_matched += ", ";
            }
        }
        finding.explanation = "Extension has permissions that allow broad access to browsing data";
        findings_.push_back(finding);
    }
    
    if (content.find("background") != std::string::npos) {
        if (content.find("service_worker") != std::string::npos || 
            content.find("persistent") != std::string::npos) {
            ExtensionFinding bg_finding = finding;
            bg_finding.risk_level = RiskLevel::Low;
            bg_finding.pattern_matched = "Background execution detected";
            bg_finding.explanation = "Extension runs code in the background";
            findings_.push_back(bg_finding);
        }
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
