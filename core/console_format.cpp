#include "console_format.h"

#include <iostream>

namespace argus {

static HANDLE GetStdoutHandle() {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

WORD ConsoleFormat::GetCurrentAttributes() {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    HANDLE h = GetStdoutHandle();
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    if (!GetConsoleScreenBufferInfo(h, &info)) return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    return info.wAttributes;
}

void ConsoleFormat::SetAttributes(WORD attrs) {
    HANDLE h = GetStdoutHandle();
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    SetConsoleTextAttribute(h, attrs);
}

WORD ConsoleFormat::GetAttributesFor(ConsoleColor color, WORD base) {
    // Preserve background and intensity bits from base where possible.
    WORD bg = base & (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY);
    WORD intensity = base & FOREGROUND_INTENSITY;

    switch (color) {
        case ConsoleColor::Default:
            return base;
        case ConsoleColor::Dim:
            return bg | (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        case ConsoleColor::Red:
            return bg | FOREGROUND_RED | FOREGROUND_INTENSITY;
        case ConsoleColor::Yellow:
            return bg | (FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY;
        case ConsoleColor::Green:
            return bg | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case ConsoleColor::Cyan:
            return bg | (FOREGROUND_GREEN | FOREGROUND_BLUE) | FOREGROUND_INTENSITY;
        case ConsoleColor::Magenta:
            return bg | (FOREGROUND_RED | FOREGROUND_BLUE) | FOREGROUND_INTENSITY;
        case ConsoleColor::White:
            return bg | (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | FOREGROUND_INTENSITY;
        default:
            return bg | (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | intensity;
    }
}

void ConsoleFormat::PrintColored(ConsoleColor color, const std::string& text) {
    WORD base = GetCurrentAttributes();
    WORD attrs = GetAttributesFor(color, base);
    SetAttributes(attrs);
    std::cout << text;
    SetAttributes(base);
}

void ConsoleFormat::PrintColoredLine(ConsoleColor color, const std::string& text) {
    PrintColored(color, text);
    std::cout << std::endl;
}

static std::string Basename(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

void ConsoleFormat::PrintThreatLine(
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
    int signalsCorroborated) {

    // Keep this compact and stable for log parsing.
    PrintColored(tagColor, "[" + tag + "]");
    std::cout << " ";
    PrintColored(severityColor, "[" + severity + "]");

    std::cout << " PID " << pid << " " << Basename(processPath);

    std::cout << " -> ";
    PrintColored(actionColor, action);

    if (!assetShort.empty()) {
        std::cout << " (" << assetShort << ")";
    }

    if (riskScore >= 0) {
        std::cout << " score=" << riskScore;
    }

    if (signalsTotal >= 0 && signalsCorroborated >= 0) {
        std::cout << " signals=" << signalsTotal << "/" << signalsCorroborated;
    }

    std::cout << std::endl;
}

} // namespace argus
