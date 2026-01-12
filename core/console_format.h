#pragma once

#include <string>
#include <windows.h>

namespace argus {

enum class ConsoleColor {
    Default,
    Dim,
    Red,
    Yellow,
    Green,
    Cyan,
    Magenta,
    White
};

class ConsoleFormat {
public:
    static void PrintColored(ConsoleColor color, const std::string& text);
    static void PrintColoredLine(ConsoleColor color, const std::string& text);

    // Prints a single compact status line with selective highlighting.
    // Example:
    //   [THREAT][HIGH] PID 1234 chrome.exe -> TERMINATED (Passwords) score=50 signals=3/2
    static void PrintThreatLine(
        const std::string& tag,
        ConsoleColor tagColor,
        const std::string& severity,
        ConsoleColor severityColor,
        uint32_t pid,
        const std::string& processPath,
        const std::string& action,
        ConsoleColor actionColor,
        const std::string& assetShort,
        int riskScore,
        int signalsTotal,
        int signalsCorroborated);

private:
    static WORD GetAttributesFor(ConsoleColor color, WORD base);
    static WORD GetCurrentAttributes();
    static void SetAttributes(WORD attrs);
};

} // namespace argus
