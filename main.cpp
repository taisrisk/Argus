#include "core/session_manager.h"
#include "core/process_monitor.h"
#include "core/network_monitor.h"
#include "core/extension_scanner.h"
#include "core/file_monitor.h"
#include "core/risk_engine.h"
#include "core/logger.h"
#include "core/credential_monitor.h"
#include "core/extension_runtime_cdp.h"
#include "core/threat_fingerprint.h"

// Keep windows.h lean and avoid winsock.h conflicts.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <windows.h>
#include <iostream>
#include <limits>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <chrono>
#include <conio.h>

static void ClearScreen() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hOut, &csbi)) return;
    DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    DWORD count;
    COORD homeCoords = {0, 0};
    FillConsoleOutputCharacterW(hOut, L' ', cellCount, homeCoords, &count);
    FillConsoleOutputAttribute(hOut, csbi.wAttributes, cellCount, homeCoords, &count);
    SetConsoleCursorPosition(hOut, homeCoords);
}

static void RenderStartupUi(bool ext_scan,
                            bool deep_scan_browser,
                            bool instant_kill_known_threats,
                            bool file_mon,
                            bool net_mon,
                            bool risk_engine,
                            bool cred_mon) {
    ClearScreen();
    std::cout << "Argus Phase 3.1 - Multi-Signal EDR Mesh" << std::endl;
    std::cout << "Toggle modules with number keys, then press 'y' to start." << std::endl;
    std::cout << std::endl;

    auto onoff = [](bool v) { return v ? "[on ]" : "[off]"; };
    std::cout << "  1) Browser extension scan     " << onoff(ext_scan) << std::endl;
    std::cout << "  2) Deep scan browser (CDP)    " << onoff(deep_scan_browser) << std::endl;
    std::cout << "  3) Instant-kill known threats " << onoff(instant_kill_known_threats) << std::endl;
    std::cout << "  4) File monitoring            " << onoff(file_mon) << std::endl;
    std::cout << "  5) Network monitoring         " << onoff(net_mon) << std::endl;
    std::cout << "  6) Risk engine                " << onoff(risk_engine) << std::endl;
    std::cout << "  7) Credential monitor         " << onoff(cred_mon) << std::endl;
    std::cout << std::endl;
    std::cout << "Press 1-7 to toggle, 'y' to start, 'q' to quit." << std::endl;
}

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
    
    // Startup UI toggles (defaults from config/argus.json consent section).
    bool extension_scan_consent = false;
    bool deep_scan_browser_enabled = false;
    bool instant_kill_known_threats = false;
    bool file_monitoring_enabled = true;
    bool network_monitoring_enabled = true;
    bool risk_engine_enabled = true;
    bool credential_monitor_enabled = true;

    // Interactive startup UI (no auto-pressing 'y').
    RenderStartupUi(extension_scan_consent,
                    deep_scan_browser_enabled,
                    instant_kill_known_threats,
                    file_monitoring_enabled,
                    network_monitoring_enabled,
                    risk_engine_enabled,
                    credential_monitor_enabled);

    for (;;) {
        int ch = _getch();
        if (ch == 'q' || ch == 'Q') {
            return 0;
        }
        if (ch == 'y' || ch == 'Y') {
            break;
        }
        switch (ch) {
            case '1': extension_scan_consent = !extension_scan_consent; break;
            case '2': deep_scan_browser_enabled = !deep_scan_browser_enabled; break;
            case '3': instant_kill_known_threats = !instant_kill_known_threats; break;
            case '4': file_monitoring_enabled = !file_monitoring_enabled; break;
            case '5': network_monitoring_enabled = !network_monitoring_enabled; break;
            case '6': risk_engine_enabled = !risk_engine_enabled; break;
            case '7': credential_monitor_enabled = !credential_monitor_enabled; break;
            default: break;
        }
        RenderStartupUi(extension_scan_consent,
                        deep_scan_browser_enabled,
                        instant_kill_known_threats,
                        file_monitoring_enabled,
                        network_monitoring_enabled,
                        risk_engine_enabled,
                        credential_monitor_enabled);
    }
    
    argus::SessionManager session;
    argus::Logger logger;
    argus::ProcessMonitor process_monitor;
    argus::NetworkMonitor network_monitor;
    argus::ExtensionScanner extension_scanner;
    argus::ExtensionRuntimeCDP extension_runtime;
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

    if (network_monitoring_enabled) {
        network_monitor.Initialize();
    }

    if (extension_scan_consent) {
        extension_scanner.Initialize(true);
    } else {
        extension_scanner.Initialize(false);
    }

    if (deep_scan_browser_enabled) {
        // Deep scan: attempt to enable/attach to Chromium CDP (may launch a browser).
        if (!extension_runtime.InitializeAndEnsureChromiumCdp()) {
            logger.Log(argus::LogLevel::Warning, "[DeepScanBrowser] CDP init failed - runtime visibility unavailable");
        }
    }

    if (file_monitoring_enabled) {
        file_monitor.Initialize();
    }

    if (risk_engine_enabled) {
        risk_engine.Initialize();
    }

    if (credential_monitor_enabled) {
        credential_monitor.Initialize();
    }
    
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
    if (extension_runtime.IsActive()) {
        logger.Log(argus::LogLevel::Info, "[ExtensionRuntime] CDP enabled on port " + std::to_string(extension_runtime.GetPort()));
    } else {
        logger.Log(argus::LogLevel::Warning, "[ExtensionRuntime] CDP disabled - runtime visibility unavailable");
    }
    
    std::cout << std::endl;
    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl;
    std::cout << std::endl;
    std::cout.flush();
    
    const int main_loop_interval = 2;
    const int extension_scan_interval_seconds = 300;
    const int event_batch_size = 10;
    
    int cycle = 0;
    size_t last_assessment_count = 0;
    
    std::cout << "Phase 3.1: Multi-signal EDR mesh + handle monitoring + signal correlation" << std::endl;
    std::cout.flush();
    
    auto last_extension_scan = std::chrono::steady_clock::now() - std::chrono::seconds(extension_scan_interval_seconds + 1);
    bool initial_extension_scan_done = false;
    
    while (g_running) {
        process_monitor.Update();
        credential_monitor.Update();

        // Instant-kill known threats (opt-in): check newly started processes against threats/ fingerprints.
        // NOTE: ConsumeNewProcesses() is populated by ProcessMonitor::Update() on its scan interval.
        if (instant_kill_known_threats) {
            auto new_procs = process_monitor.ConsumeNewProcesses();
            for (const auto& p : new_procs) {
                if (p.image_path.empty()) continue;

                std::wstring wpath;
                {
                    int len = MultiByteToWideChar(CP_UTF8, 0, p.image_path.c_str(), -1, nullptr, 0);
                    if (len > 0) {
                        wpath.resize(static_cast<size_t>(len - 1));
                        MultiByteToWideChar(CP_UTF8, 0, p.image_path.c_str(), -1, &wpath[0], len);
                    }
                }
                if (wpath.empty()) continue;

                std::string sha;
                std::string err;
                if (!argus::ThreatFingerprint::ComputeFileSha256(wpath, sha, err)) {
                    continue;
                }

                if (argus::ThreatFingerprint::IsKnownBadSha256(sha)) {
                    logger.Log(argus::LogLevel::Warning,
                               std::string("[InstantKill] Known threat hash match: ") + sha + " pid=" + std::to_string(p.pid));

                    std::string summary;
                    if (!argus::ThreatFingerprint::LoadThreatSummary(sha, summary)) {
                        summary = "Known threat fingerprint matched\n";
                        summary += "  sha256: " + sha + "\n";
                    }

                    std::cout << "\n[AUTO-BLOCKED] Prevented known threat from running\n"
                              << summary
                              << "  current_pid: " << p.pid << "\n"
                              << "  current_image_path: " << p.image_path << "\n"
                              << std::endl;
                    // Best-effort: terminate immediately.
                    credential_monitor.KillProcess(p.pid);
                }
            }
        }

        // Deep scan browser (CDP) only runs if enabled at startup.
        if (extension_runtime.IsActive()) {
            extension_runtime.Update();
            auto cdp_events = extension_runtime.GetRecentEvents(5);
            for (const auto& e : cdp_events) {
                if (e.type == "warning") {
                    logger.Log(argus::LogLevel::Warning, std::string("[ExtensionRuntime] ") + e.details);
                }
            }
        }
        
        auto browser_pids = process_monitor.GetBrowserPids();
        credential_monitor.SetBrowserProcessIds(browser_pids);
        network_monitor.SetTrackedProcesses(browser_pids);
        file_monitor.SetBrowserProcessIds(browser_pids);
        
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
        
        if (extension_scan_consent && !initial_extension_scan_done) {
            std::cout << "\n=== Initial Extension Scan (One-Time) ===" << std::endl;
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
                                
                                extension_scanner.PerformInitialScan(profile_path);
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
                
                if (!credential_monitor.AreWatchersRunning()) {
                    credential_monitor.StartDirectoryWatchers();
                }
                
                extension_scanner.StartActivityMonitoring();
                std::cout << "[ExtensionScanner] Real-time activity monitoring enabled" << std::endl;
                
                if (localappdata) free(localappdata);
                if (appdata) free(appdata);
            } else {
                std::cerr << "Failed to get environment variables" << std::endl;
                logger.Log(argus::LogLevel::Error, "Failed to get environment variables");
            }
            
            initial_extension_scan_done = true;
            std::cout << "\n[SYSTEM] Extension scan complete. Entering continuous monitoring mode." << std::endl;
            std::cout.flush();
        }
        
        if (extension_scan_consent && initial_extension_scan_done) {
            extension_scanner.UpdateActivityMonitoring();
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
    std::cout << "\nPress Enter to exit...";
    std::cout.flush();
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
    std::cin.get();
    
    return 0;
}
