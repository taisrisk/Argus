#include "credential_monitor.h"
#include <windows.h>
#include <algorithm>
#include <iostream>

namespace argus {

CredentialMonitor::CredentialMonitor() 
    : is_active_(false) {
}

CredentialMonitor::~CredentialMonitor() {
    if (is_active_) {
        Shutdown();
    }
}

bool CredentialMonitor::Initialize() {
    if (is_active_) {
        return false;
    }
    
    is_active_ = true;
    last_check_ = std::chrono::system_clock::now();
    
    return true;
}

void CredentialMonitor::Shutdown() {
    if (!is_active_) {
        return;
    }
    
    is_active_ = false;
    asset_registry_.clear();
    browser_pids_.clear();
    active_chains_.clear();
}

void CredentialMonitor::RegisterBrowserProfile(const std::string& browser, const std::string& profile_path) {
    if (!is_active_) {
        return;
    }
    
    SensitiveAsset cookies_asset;
    cookies_asset.browser = browser;
    cookies_asset.profile = profile_path;
    cookies_asset.file_path = profile_path + "\\Network\\Cookies";
    cookies_asset.type = AssetType::Cookies;
    cookies_asset.is_decoy = false;
    asset_registry_.push_back(cookies_asset);
    
    SensitiveAsset login_asset;
    login_asset.browser = browser;
    login_asset.profile = profile_path;
    login_asset.file_path = profile_path + "\\Login Data";
    login_asset.type = AssetType::LoginData;
    login_asset.is_decoy = false;
    asset_registry_.push_back(login_asset);
    
    SensitiveAsset state_asset;
    state_asset.browser = browser;
    state_asset.profile = profile_path;
    state_asset.file_path = profile_path + "\\Local State";
    state_asset.type = AssetType::LocalState;
    state_asset.is_decoy = false;
    asset_registry_.push_back(state_asset);
    
    SensitiveAsset webdata_asset;
    webdata_asset.browser = browser;
    webdata_asset.profile = profile_path;
    webdata_asset.file_path = profile_path + "\\Web Data";
    webdata_asset.type = AssetType::WebData;
    webdata_asset.is_decoy = false;
    asset_registry_.push_back(webdata_asset);
}

void CredentialMonitor::SetBrowserProcessIds(const std::vector<uint32_t>& pids) {
    browser_pids_ = pids;
}

void CredentialMonitor::Update() {
    if (!is_active_) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_check_).count();
    
    if (elapsed >= 5) {
        MonitorFileAccess();
        AnalyzeAccessPatterns();
        last_check_ = now;
    }
}

std::vector<ThreatChain> CredentialMonitor::GetActiveThreats() {
    std::vector<ThreatChain> threats;
    
    for (const auto& pair : active_chains_) {
        if (pair.second.risk_score >= 5) {
            threats.push_back(pair.second);
        }
    }
    
    return threats;
}

void CredentialMonitor::BuildAssetRegistry() {
}

void CredentialMonitor::CreateDecoyProfile(const std::string& browser, const std::string& base_path) {
}

void CredentialMonitor::MonitorFileAccess() {
}

void CredentialMonitor::AnalyzeAccessPatterns() {
    auto now = std::chrono::system_clock::now();
    
    std::vector<uint32_t> expired_pids;
    for (auto& pair : active_chains_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.last_event).count();
        if (age > 60) {
            expired_pids.push_back(pair.first);
        }
    }
    
    for (uint32_t pid : expired_pids) {
        active_chains_.erase(pid);
    }
}

int CredentialMonitor::CalculateRiskScore(const ThreatChain& chain) {
    int score = 0;
    
    std::set<AssetType> accessed_types;
    for (const auto& event : chain.events) {
        accessed_types.insert(event.asset_type);
        
        if (event.is_decoy_hit) {
            score += 10;
        }
    }
    
    if (accessed_types.count(AssetType::Cookies)) score += 2;
    if (accessed_types.count(AssetType::LoginData)) score += 3;
    if (accessed_types.count(AssetType::LocalState)) score += 4;
    if (accessed_types.count(AssetType::WebData)) score += 2;
    
    if (accessed_types.size() >= 2) {
        score += 3;
    }
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        chain.last_event - chain.first_event).count();
    if (duration <= 15) {
        score += 2;
    }
    
    return score;
}

bool CredentialMonitor::IsProcessSuspicious(uint32_t pid) {
    return std::find(browser_pids_.begin(), browser_pids_.end(), pid) == browser_pids_.end();
}

}
