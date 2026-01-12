#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace argus {

struct ThreatFingerprintResult {
    bool ok = false;
    std::string error;

    std::string image_path;
    std::string sha256;

    bool signature_checked = false;
    bool signature_valid = false;
    std::string signature_summary;

    std::string output_dir; // threats/<sha256>
};

class ThreatFingerprint {
public:
    // Captures a fingerprint bundle for a running process.
    // Writes into threats/<sha256>/
    static ThreatFingerprintResult CaptureForPid(uint32_t pid,
                                                 const std::string& reason,
                                                 const std::string& classification,
                                                 const std::vector<std::string>& accessed_files);

    // Computes SHA-256 of a file on disk.
    static bool ComputeFileSha256(const std::wstring& path, std::string& out_hex, std::string& out_error);

    // Checks Authenticode signature (best-effort).
    static bool CheckAuthenticodeSignature(const std::wstring& path,
                                          bool& out_valid,
                                          std::string& out_summary,
                                          std::string& out_error);

    // Extracts PE headers (DOS + NT + section table) into a byte buffer.
    static bool ExtractPeHeaders(const std::wstring& path, std::vector<uint8_t>& out_bytes, std::string& out_error);

    // Loads known-bad SHA-256 hashes from threats/ (hashes.json) and/or threats/blacklist.txt.
    static void LoadKnownBadSha256(std::vector<std::string>& out_hashes);

    static bool IsKnownBadSha256(const std::string& sha256);

    // Loads a short human-readable summary for a known threat hash from threats/<sha256>/meta.json.
    // Best-effort, dependency-free parsing.
    static bool LoadThreatSummary(const std::string& sha256, std::string& out_summary);

private:
    static std::wstring GetProcessImagePathW(uint32_t pid, std::string& out_error);
    static bool EnsureDir(const std::wstring& path, std::string& out_error);
    static bool WriteAllBytes(const std::wstring& path, const void* data, size_t len, std::string& out_error);
    static bool WriteAllTextUtf8(const std::wstring& path, const std::string& text, std::string& out_error);
    static std::string ToHexLower(const uint8_t* data, size_t len);
};

} // namespace argus
