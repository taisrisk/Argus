#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace argus {

struct CdpRuntimeEvent {
    std::chrono::system_clock::time_point timestamp;
    std::string type;          // e.g. "cdp_ready", "target_list", "warning"
    std::string details;       // human-readable
    int port = 0;
    std::vector<std::string> targets; // raw target summaries
};

class ExtensionRuntimeCDP {
public:
    ExtensionRuntimeCDP();
    ~ExtensionRuntimeCDP();

    // Enables CDP on an already-running Chromium browser if possible.
    // If no supported browser is running, it will launch one.
    // If a port is already in use, it will probe for another.
    bool InitializeAndEnsureChromiumCdp();

    void Shutdown();

    // Polls the CDP /json endpoint and emits events.
    void Update();

    bool IsActive() const { return is_active_; }
    int GetPort() const { return port_; }

    std::vector<CdpRuntimeEvent> GetRecentEvents(int max_count = 100);

private:
    bool is_active_;
    int port_;
    std::chrono::steady_clock::time_point last_poll_;
    std::vector<CdpRuntimeEvent> events_;

    // Port selection
    static bool IsPortListening(int port);
    static int FindFreePort(int start_port, int max_tries);

    // Launch
    static bool LaunchChromiumFromConfigOrDefault(const std::wstring& args);

    // Process detection
    static bool IsAnySupportedChromiumRunning();

    // Config helpers
    static std::wstring ExpandEnvVars(const std::wstring& s);
    static std::wstring ReadArgusJsonText();
    static std::vector<std::wstring> ExtractEnabledChromiumProfileRoots(const std::wstring& json_text);

    // HTTP
    static bool HttpGetLocalhostJson(int port, std::string& out_body);
    static std::vector<std::string> ExtractTargetSummaries(const std::string& json);

    void PushEvent(const CdpRuntimeEvent& e);
};

} // namespace argus
