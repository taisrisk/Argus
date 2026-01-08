#include "core/session_manager.h"
#include "core/process_monitor.h"
#include "core/network_monitor.h"
#include "core/extension_scanner.h"
#include "core/file_monitor.h"
#include "core/risk_engine.h"
#include "core/logger.h"
#include "core/credential_monitor.h"
#include <windows.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <chrono>

std::atomic<bool> g_running(true);

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char* argv[]) {
if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
    std::cerr << "Failed to set console handler" << std::endl;
    return 1;
}
    
std::cout << "Argus Phase 2.6 - Browser Security Monitor" << std::endl;
std::cout << "Read-only | Local-only | Active defense" << std::endl;
std::cout << std::endl;
    
bool extension_scan_consent = false;
std::cout << "Allow Argus to scan extension files (local, read-only)? (y/n): ";
std::cout.flush();
    
char consent;
std::cin >> consent;
std::cin.ignore(10000, '\n');
    
extension_scan_consent = (consent == 'y' || consent == 'Y');
    
std::cout << "You selected: " << (extension_scan_consent ? "YES" : "NO") << std::endl;
std::cout.flush();
    
    argus::SessionManager session;
    argus::Logger logger;
    argus::ProcessMonitor process_monitor;
    argus::NetworkMonitor network_monitor;
    argus::ExtensionScanner extension_scanner;
    argus::FileMonitor file_monitor;
    argus::RiskEngine risk_engine;
    argus::CredentialMonitor credential_monitor;
    
    if (!session.Initialize()) {
        std::cerr << "Failed to initialize session manager" << std::endl;
        return 1;
    }
    
    std::cout << "Session ID: " << session.GetSessionId() << std::endl;
    
    if (!logger.Initialize(session.GetSessionId())) {
        std::cerr << "Failed to initialize logger" << std::endl;
        session.Shutdown();
        return 1;
    }
    
    logger.Log(argus::LogLevel::Info, "Initializing Argus monitors");
    
    process_monitor.Initialize();
    network_monitor.Initialize();
    extension_scanner.Initialize(extension_scan_consent);
    file_monitor.Initialize();
    risk_engine.Initialize();
    credential_monitor.Initialize();
    
    char* localappdata = nullptr;
    size_t localappdata_len = 0;
    char* appdata = nullptr;
    size_t appdata_len = 0;
    
    _dupenv_s(&localappdata, &localappdata_len, "LOCALAPPDATA");
    _dupenv_s(&appdata, &appdata_len, "APPDATA");
    
    if (localappdata || appdata) {
        struct BrowserDef {
            std::string id;
            std::string name;
            std::string path;
        };
        
        std::vector<BrowserDef> browsers;
        
        if (localappdata) {
            browsers.push_back({"chrome", "Chrome", std::string(localappdata) + "\\Google\\Chrome\\User Data"});
            browsers.push_back({"edge", "Edge", std::string(localappdata) + "\\Microsoft\\Edge\\User Data"});
            browsers.push_back({"brave", "Brave", std::string(localappdata) + "\\BraveSoftware\\Brave-Browser\\User Data"});
            browsers.push_back({"vivaldi", "Vivaldi", std::string(localappdata) + "\\Vivaldi\\User Data"});
            browsers.push_back({"comet", "Perplexity Comet", std::string(localappdata) + "\\Perplexity\\Comet\\User Data"});
        }
        if (appdata) {
            browsers.push_back({"opera", "Opera", std::string(appdata) + "\\Opera Software\\Opera Stable"});
            browsers.push_back({"opera_gx", "Opera GX", std::string(appdata) + "\\Opera Software\\Opera GX Stable"});
        }
        
        for (const auto& browser : browsers) {
            WIN32_FIND_DATAA find_data;
            HANDLE hFind = FindFirstFileA((browser.path + "\\*").c_str(), &find_data);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        std::string dir_name = find_data.cFileName;
                        if (dir_name == "Default" || dir_name.find("Profile") == 0) {
                            std::string profile_path = browser.path + "\\" + dir_name;
                            credential_monitor.RegisterBrowserProfile(browser.id, profile_path);
                        }
                    }
                } while (FindNextFileA(hFind, &find_data));
                FindClose(hFind);
            }
        }
        
        credential_monitor.StartDirectoryWatchers();
        std::cout << "[CredentialMonitor] Protection active for all profiles" << std::endl;
        
        if (localappdata) free(localappdata);
        if (appdata) free(appdata);
    }
    
    session.RegisterCleanupCallback([&]() {
        try { credential_monitor.Shutdown(); } catch (...) {}
    });
    session.RegisterCleanupCallback([&]() {
        try { risk_engine.Shutdown(); } catch (...) {}
    });
    session.RegisterCleanupCallback([&]() {
        try { file_monitor.Shutdown(); } catch (...) {}
    });
    session.RegisterCleanupCallback([&]() {
        try { extension_scanner.Shutdown(); } catch (...) {}
    });
    session.RegisterCleanupCallback([&]() {
        try { network_monitor.Shutdown(); } catch (...) {}
    });
    session.RegisterCleanupCallback([&]() {
        try { process_monitor.Shutdown(); } catch (...) {}
    });
    session.RegisterCleanupCallback([&]() {
        try { logger.Shutdown(); } catch (...) {}
    });
    
    logger.Log(argus::LogLevel::Info, "All monitors initialized successfully");
    logger.Log(argus::LogLevel::Info, extension_scan_consent ? 
               "Extension scanning: ENABLED" : "Extension scanning: DISABLED");
    
    std::cout << std::endl;
    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl;
    std::cout << std::endl;
    std::cout.flush();
    
    const int main_loop_interval = 2;
    const int extension_scan_interval_seconds = 300;
    const int event_batch_size = 10;
    
    int cycle = 0;
    size_t last_assessment_count = 0;
    
    std::cout << "Phase 2.6: Active defense + automatic threat termination" << std::endl;
    std::cout.flush();
    
    auto last_extension_scan = std::chrono::steady_clock::now() - std::chrono::seconds(extension_scan_interval_seconds + 1);
    
    while (g_running) {
        process_monitor.Update();
        credential_monitor.Update();
        
        credential_monitor.SetBrowserProcessIds(process_monitor.GetBrowserPids());
        
        if (process_monitor.IsBrowserActive()) {
            network_monitor.Update();
            file_monitor.Update();
            
            auto network_events = network_monitor.GetRecentEvents(event_batch_size);
            if (!network_events.empty()) {
                risk_engine.AnalyzeNetworkEvents(network_events);
            }
            
            auto file_events = file_monitor.GetRecentEvents(event_batch_size);
            if (!file_events.empty()) {
                risk_engine.AnalyzeFileEvents(file_events);
            }
        }
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_extension_scan).count();
        
        if (extension_scan_consent && elapsed >= extension_scan_interval_seconds) {
            std::cout << "\n=== Extension Scan ===" << std::endl;
            
            char* localappdata = nullptr;
            size_t localappdata_len = 0;
            char* appdata = nullptr;
            size_t appdata_len = 0;
            
            _dupenv_s(&localappdata, &localappdata_len, "LOCALAPPDATA");
            _dupenv_s(&appdata, &appdata_len, "APPDATA");
            
            extension_scanner.ClearFindings();
            
            if (localappdata != nullptr || appdata != nullptr) {
                struct BrowserDef {
                    std::string id;
                    std::string name;
                    std::string path;
                };
                
                std::vector<BrowserDef> browsers;
                
                if (localappdata) {
                    browsers.push_back({"chrome", "Chrome", std::string(localappdata) + "\\Google\\Chrome\\User Data"});
                    browsers.push_back({"edge", "Edge", std::string(localappdata) + "\\Microsoft\\Edge\\User Data"});
                    browsers.push_back({"brave", "Brave", std::string(localappdata) + "\\BraveSoftware\\Brave-Browser\\User Data"});
                    browsers.push_back({"vivaldi", "Vivaldi", std::string(localappdata) + "\\Vivaldi\\User Data"});
                    browsers.push_back({"comet", "Perplexity Comet", std::string(localappdata) + "\\Perplexity\\Comet\\User Data"});
                }
                if (appdata) {
                    browsers.push_back({"opera", "Opera", std::string(appdata) + "\\Opera Software\\Opera Stable"});
                    browsers.push_back({"opera_gx", "Opera GX", std::string(appdata) + "\\Opera Software\\Opera GX Stable"});
                }
                
                int total_profiles = 0;
                int total_files_monitored = 0;
                
                std::cout << "\n=== Browser Discovery ===" << std::endl;
                
                for (const auto& browser : browsers) {
                    WIN32_FIND_DATAA find_data;
                    HANDLE hFind = FindFirstFileA((browser.path + "\\*").c_str(), &find_data);
                    
                    if (hFind == INVALID_HANDLE_VALUE) {
                        continue;
                    }
                    
                    std::cout << "\n[" << browser.name << "]" << std::endl;
                    
                    do {
                        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            std::string dir_name = find_data.cFileName;
                            if (dir_name == "Default" || dir_name.find("Profile") == 0) {
                                std::string profile_path = browser.path + "\\" + dir_name;
                                
                                extension_scanner.ScanExtensions(profile_path);
                                auto status = credential_monitor.RegisterBrowserProfileWithStatus(browser.id, profile_path);
                                
                                std::string status_str;
                                if (status.files_monitored == 0) {
                                    status_str = "FAIL";
                                } else if (status.missing_files.empty()) {
                                    status_str = "OK";
                                } else {
                                    status_str = "PARTIAL";
                                }
                                
                                std::cout << "  " << dir_name << ": " << status_str;
                                std::cout << " (" << status.files_monitored << " files)" << std::endl;
                                
                                if (!status.monitored_files.empty() && status_str != "OK") {
                                    std::cout << "    Monitoring: ";
                                    for (size_t i = 0; i < status.monitored_files.size(); ++i) {
                                        std::cout << status.monitored_files[i];
                                        if (i < status.monitored_files.size() - 1) std::cout << ", ";
                                    }
                                    std::cout << std::endl;
                                }
                                
                                if (!status.missing_files.empty()) {
                                    std::cout << "    Missing: ";
                                    for (size_t i = 0; i < status.missing_files.size(); ++i) {
                                        std::cout << status.missing_files[i];
                                        if (i < status.missing_files.size() - 1) std::cout << ", ";
                                    }
                                    std::cout << std::endl;
                                }
                                
                                total_profiles++;
                                total_files_monitored += status.files_monitored;
                            }
                        }
                    } while (FindNextFileA(hFind, &find_data));
                    
                    FindClose(hFind);
                }
                
                std::cout << "\n=== Monitoring Summary ===" << std::endl;
                std::cout << "Browsers: " << browsers.size() << std::endl;
                std::cout << "Profiles: " << total_profiles << std::endl;
                std::cout << "Files monitored: " << total_files_monitored << std::endl;
                
                auto findings = extension_scanner.GetFindings();
                
                if (!findings.empty()) {
                    std::cout << "\nRisky Extensions: " << findings.size() << " found" << std::endl;
                    for (const auto& f : findings) {
                        std::cout << "  - " << f.extension_name << ": " << f.pattern_matched << std::endl;
                    }
                    risk_engine.AnalyzeExtensionFindings(findings);
                    logger.Log(argus::LogLevel::Info, 
                              "Extension scan: " + std::to_string(findings.size()) + " risky extensions");
                }
                
                std::cout << "\n=== Credential Protection Active ===" << std::endl;
                std::cout << "Watching for unauthorized access to browser credentials..." << std::endl;
                
                credential_monitor.StartDirectoryWatchers();
                
                if (localappdata) free(localappdata);
                if (appdata) free(appdata);
            } else {
                std::cerr << "Failed to get environment variables" << std::endl;
                logger.Log(argus::LogLevel::Error, "Failed to get environment variables");
            }
            
            last_extension_scan = now;
        }
        
        auto assessments = risk_engine.GetAssessments();
        
        auto threats = credential_monitor.GetActiveThreats();
        if (!threats.empty()) {
            risk_engine.AnalyzeCredentialThreats(threats);
            assessments = risk_engine.GetAssessments();
        }
        
        if (assessments.size() > last_assessment_count) {
            for (size_t i = last_assessment_count; i < assessments.size(); ++i) {
                const auto& assessment = assessments[i];
                std::string risk_str;
                switch (assessment.level) {
                    case argus::RiskLevel::High: risk_str = "HIGH"; break;
                    case argus::RiskLevel::Medium: risk_str = "MEDIUM"; break;
                    case argus::RiskLevel::Low: risk_str = "LOW"; break;
                    default: risk_str = "INFO"; break;
                }
                
                std::cout << "[" << risk_str << "] " << assessment.category << ": " << assessment.explanation << std::endl;
                logger.Log(argus::LogLevel::Warning, 
                          "[" + risk_str + "] " + assessment.category + ": " + assessment.explanation);
            }
            last_assessment_count = assessments.size();
        }
        
        if (cycle % 100 == 0 && cycle > 0) {
            risk_engine.ClearOldAssessments();
            last_assessment_count = risk_engine.GetAssessments().size();
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(main_loop_interval));
        cycle++;
    }
    
    std::cout << std::endl;
    std::cout << "Shutting down..." << std::endl;
    logger.Log(argus::LogLevel::Info, "Shutdown initiated");
    
    session.Shutdown();
    
    std::cout << "Argus session ended. No persistence. No residue." << std::endl;
    std::cout << "Log file: logs\\" << session.GetSessionId() << ".log" << std::endl;
    
    return 0;
}
