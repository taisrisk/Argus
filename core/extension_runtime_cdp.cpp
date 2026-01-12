#include "extension_runtime_cdp.h"

// Prevent winsock.h from being pulled in by windows.h.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <sstream>
#include <fstream>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace argus {

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring out;
    out.resize(static_cast<size_t>(len - 1));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len);
    return out;
}

static std::wstring ToLowerW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

std::wstring ExtensionRuntimeCDP::ExpandEnvVars(const std::wstring& s) {
    if (s.empty()) return L"";
    DWORD needed = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (needed == 0) return s;
    std::wstring out;
    out.resize(needed);
    DWORD written = ExpandEnvironmentStringsW(s.c_str(), &out[0], needed);
    if (written == 0) return s;
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

std::wstring ExtensionRuntimeCDP::ReadArgusJsonText() {
    std::ifstream f("config/argus.json", std::ios::in | std::ios::binary);
    if (!f) return L"";
    std::string bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return Utf8ToWide(bytes);
}

std::vector<std::wstring> ExtensionRuntimeCDP::ExtractEnabledChromiumProfileRoots(const std::wstring& json_text) {
    // Minimal extraction: find occurrences of "type":"chromium" and then the next "profile_root":"...".
    // This is intentionally lightweight to avoid adding a JSON dependency.
    std::vector<std::wstring> roots;
    std::wstring s = json_text;
    size_t pos = 0;
    while (true) {
        size_t typePos = s.find(L"\"type\"", pos);
        if (typePos == std::wstring::npos) break;
        size_t colon = s.find(L':', typePos);
        if (colon == std::wstring::npos) break;
        size_t q1 = s.find(L'\"', colon);
        if (q1 == std::wstring::npos) break;
        size_t q2 = s.find(L'\"', q1 + 1);
        if (q2 == std::wstring::npos) break;
        std::wstring typeVal = s.substr(q1 + 1, q2 - q1 - 1);

        if (ToLowerW(typeVal) == L"chromium") {
            size_t prPos = s.find(L"\"profile_root\"", q2);
            if (prPos != std::wstring::npos) {
                size_t prColon = s.find(L':', prPos);
                size_t prQ1 = (prColon != std::wstring::npos) ? s.find(L'\"', prColon) : std::wstring::npos;
                size_t prQ2 = (prQ1 != std::wstring::npos) ? s.find(L'\"', prQ1 + 1) : std::wstring::npos;
                if (prQ2 != std::wstring::npos) {
                    std::wstring root = s.substr(prQ1 + 1, prQ2 - prQ1 - 1);
                    root = ExpandEnvVars(root);
                    if (!root.empty()) {
                        roots.push_back(root);
                    }
                }
            }
        }

        pos = q2 + 1;
    }
    // Dedup
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    return roots;
}

bool ExtensionRuntimeCDP::IsAnySupportedChromiumRunning() {
    // Chromium-based executables we know about (from argus.json list).
    const wchar_t* names[] = {L"chrome.exe", L"msedge.exe", L"brave.exe", L"opera.exe", L"vivaldi.exe", L"comet.exe"};

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            std::wstring exe = ToLowerW(pe.szExeFile);
            for (auto* n : names) {
                if (exe == n) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return found;
}

ExtensionRuntimeCDP::ExtensionRuntimeCDP()
    : is_active_(false), port_(0), last_poll_(std::chrono::steady_clock::now()) {
}

ExtensionRuntimeCDP::~ExtensionRuntimeCDP() {
    Shutdown();
}

void ExtensionRuntimeCDP::PushEvent(const CdpRuntimeEvent& e) {
    events_.push_back(e);
    const size_t max_events = 200;
    if (events_.size() > max_events) {
        events_.erase(events_.begin(), events_.begin() + (events_.size() - max_events));
    }
}

bool ExtensionRuntimeCDP::IsPortListening(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<u_short>(port));

    // Non-blocking connect with short timeout.
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        closesocket(s);
        return true;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 150 * 1000;

    rc = select(0, nullptr, &wfds, nullptr, &tv);
    if (rc > 0 && FD_ISSET(s, &wfds)) {
        int err = 0;
        int errlen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
        closesocket(s);
        return err == 0;
    }

    closesocket(s);
    return false;
}

int ExtensionRuntimeCDP::FindFreePort(int start_port, int max_tries) {
    // Find a port that is NOT currently listening.
    for (int i = 0; i < max_tries; ++i) {
        int p = start_port + i;
        if (!IsPortListening(p)) {
            return p;
        }
    }
    return 0;
}

bool ExtensionRuntimeCDP::LaunchChromiumFromConfigOrDefault(const std::wstring& args) {
    // Do NOT open profile folders in Explorer.
    // Without a known browser executable path, we cannot reliably launch Chromium with flags.
    // So we only attempt to launch the system default browser with args (best-effort).
    // If the default browser is non-Chromium or ignores flags, CDP won't be available.
    HINSTANCE h = ShellExecuteW(nullptr, L"open", L"about:blank", args.c_str(), nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(h) > 32;
}

bool ExtensionRuntimeCDP::HttpGetLocalhostJson(int port, std::string& out_body) {
    out_body.clear();

    HINTERNET hSession = WinHttpOpen(L"Argus/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", static_cast<INTERNET_PORT>(port), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/json", nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Tight timeouts to avoid stalling the main loop.
    WinHttpSetTimeouts(hRequest, 200, 200, 200, 400);

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    ok = WinHttpReceiveResponse(hRequest, nullptr);
    if (!ok) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD size = 0;
    do {
        size = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &size)) break;
        if (size == 0) break;

        std::string chunk;
        chunk.resize(size);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &chunk[0], size, &read)) break;
        chunk.resize(read);
        out_body += chunk;
    } while (size > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return !out_body.empty();
}

std::vector<std::string> ExtensionRuntimeCDP::ExtractTargetSummaries(const std::string& json) {
    // Minimal, dependency-free extraction.
    // We look for occurrences of "type":"..." and "url":"..." and "title":"...".
    // This is intentionally lightweight; we can replace with a real JSON parser later.
    std::vector<std::string> out;

    size_t pos = 0;
    while (true) {
        size_t typePos = json.find("\"type\"", pos);
        if (typePos == std::string::npos) break;

        auto readStringValue = [&](size_t keyPos) -> std::string {
            size_t colon = json.find(':', keyPos);
            if (colon == std::string::npos) return "";
            size_t q1 = json.find('"', colon);
            if (q1 == std::string::npos) return "";
            size_t q2 = json.find('"', q1 + 1);
            if (q2 == std::string::npos) return "";
            return json.substr(q1 + 1, q2 - q1 - 1);
        };

        std::string type = readStringValue(typePos);

        size_t urlPos = json.find("\"url\"", typePos);
        std::string url = (urlPos != std::string::npos) ? readStringValue(urlPos) : "";

        size_t titlePos = json.find("\"title\"", typePos);
        std::string title = (titlePos != std::string::npos) ? readStringValue(titlePos) : "";

        std::ostringstream oss;
        oss << type;
        if (!title.empty()) oss << " | " << title;
        if (!url.empty()) oss << " | " << url;
        out.push_back(oss.str());

        pos = typePos + 6;
        if (out.size() >= 50) break;
    }

    return out;
}

bool ExtensionRuntimeCDP::InitializeAndEnsureChromiumCdp() {
    if (is_active_) return true;

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return false;
    }

    // If 9222 is already listening and responds, reuse it.
    int chosen = 0;
    if (IsPortListening(9222)) {
        std::string body;
        if (HttpGetLocalhostJson(9222, body)) {
            chosen = 9222;
        }
    }

    if (chosen == 0) {
        chosen = FindFreePort(9222, 50);
    }

    if (chosen == 0) {
        CdpRuntimeEvent e;
        e.timestamp = std::chrono::system_clock::now();
        e.type = "warning";
        e.details = "Could not find a free remote debugging port";
        PushEvent(e);
        return false;
    }

    port_ = chosen;

    std::wstringstream args;
    args << L"--remote-debugging-port=" << port_;

    bool launched = false;

    // If a supported Chromium browser is already running, do NOT open any URL.
    // We can only attach if it was started with --remote-debugging-port already.
    // So we just probe /json and report status.
    if (IsAnySupportedChromiumRunning()) {
        std::string body;
        if (HttpGetLocalhostJson(port_, body)) {
            launched = true; // "ready" without launching
        }
    }

    // Otherwise, try to launch a Chromium browser using config hints.
    if (!launched) {
        launched = LaunchChromiumFromConfigOrDefault(args.str());
    }

    CdpRuntimeEvent e;
    e.timestamp = std::chrono::system_clock::now();
    e.port = port_;
    e.type = launched ? "cdp_launch" : "warning";
    e.details = launched
                    ? "Ensured Chromium CDP is available (or launched a browser to attempt enabling it)"
                    : "Could not ensure Chromium CDP (no supported browser running and launch attempt failed)";
    PushEvent(e);

    is_active_ = true;
    last_poll_ = std::chrono::steady_clock::now() - std::chrono::seconds(10);
    return true;
}

void ExtensionRuntimeCDP::Shutdown() {
    if (!is_active_) return;
    is_active_ = false;
    port_ = 0;
    events_.clear();
    WSACleanup();
}

void ExtensionRuntimeCDP::Update() {
    if (!is_active_ || port_ == 0) return;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_poll_).count();
    if (elapsed < 2000) {
        return;
    }
    last_poll_ = now;

    std::string body;
    if (!HttpGetLocalhostJson(port_, body)) {
        CdpRuntimeEvent e;
        e.timestamp = std::chrono::system_clock::now();
        e.port = port_;
        e.type = "warning";
        e.details = "CDP endpoint not reachable at /json (default browser may not support Chromium flags)";
        PushEvent(e);
        return;
    }

    CdpRuntimeEvent e;
    e.timestamp = std::chrono::system_clock::now();
    e.port = port_;
    e.type = "target_list";
    e.details = "Fetched CDP target list";
    e.targets = ExtractTargetSummaries(body);
    PushEvent(e);
}

std::vector<CdpRuntimeEvent> ExtensionRuntimeCDP::GetRecentEvents(int max_count) {
    if (events_.size() <= static_cast<size_t>(max_count)) {
        return events_;
    }
    return std::vector<CdpRuntimeEvent>(events_.end() - max_count, events_.end());
}

} // namespace argus
