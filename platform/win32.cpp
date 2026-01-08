#include <windows.h>
#include <string>

namespace argus {
namespace platform {

std::string GetUserProfilePath() {
    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (GetEnvironmentVariableA("USERPROFILE", path, size) > 0) {
        return std::string(path);
    }
    return "";
}

std::string GetLocalAppDataPath() {
    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (GetEnvironmentVariableA("LOCALAPPDATA", path, size) > 0) {
        return std::string(path);
    }
    return "";
}

std::string GetChromePath() {
    std::string appdata = GetLocalAppDataPath();
    if (!appdata.empty()) {
        return appdata + "\\Google\\Chrome\\User Data\\Default";
    }
    return "";
}

std::string GetEdgePath() {
    std::string appdata = GetLocalAppDataPath();
    if (!appdata.empty()) {
        return appdata + "\\Microsoft\\Edge\\User Data\\Default";
    }
    return "";
}

std::string GetFirefoxPath() {
    std::string appdata = GetUserProfilePath();
    if (!appdata.empty()) {
        return appdata + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles";
    }
    return "";
}

}
}
