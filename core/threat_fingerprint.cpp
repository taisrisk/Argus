#include "threat_fingerprint.h"

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
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <psapi.h>

#include <algorithm>
#include <fstream>
#include <sstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

namespace argus {

static std::wstring Utf8ToWideLocal(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring out;
    out.resize(static_cast<size_t>(len - 1));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len);
    return out;
}

static std::string WideToUtf8Local(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string out;
    out.resize(static_cast<size_t>(len - 1));
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr);
    return out;
}

std::string ThreatFingerprint::ToHexLower(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2 + 0] = kHex[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[(data[i] >> 0) & 0xF];
    }
    return out;
}

bool ThreatFingerprint::WriteAllBytes(const std::wstring& path, const void* data, size_t len, std::string& out_error) {
    out_error.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        out_error = "CreateFileW failed";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr);
    CloseHandle(h);
    if (!ok || written != len) {
        out_error = "WriteFile failed";
        return false;
    }
    return true;
}

bool ThreatFingerprint::WriteAllTextUtf8(const std::wstring& path, const std::string& text, std::string& out_error) {
    return WriteAllBytes(path, text.data(), text.size(), out_error);
}

bool ThreatFingerprint::EnsureDir(const std::wstring& path, std::string& out_error) {
    out_error.clear();
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    DWORD e = GetLastError();
    if (e == ERROR_ALREADY_EXISTS) return true;
    out_error = "CreateDirectoryW failed";
    return false;
}

std::wstring ThreatFingerprint::GetProcessImagePathW(uint32_t pid, std::string& out_error) {
    out_error.clear();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        out_error = "OpenProcess failed";
        return L"";
    }

    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(h, 0, buf, &size)) {
        CloseHandle(h);
        out_error = "QueryFullProcessImageNameW failed";
        return L"";
    }
    CloseHandle(h);
    return std::wstring(buf, buf + size);
}

bool ThreatFingerprint::ComputeFileSha256(const std::wstring& path, std::string& out_hex, std::string& out_error) {
    out_hex.clear();
    out_error.clear();

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        out_error = "CreateFileW(open) failed";
        return false;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        out_error = "CryptAcquireContextW failed";
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        out_error = "CryptCreateHash failed";
        return false;
    }

    std::vector<uint8_t> buf(64 * 1024);
    DWORD read = 0;
    while (ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) && read > 0) {
        if (!CryptHashData(hHash, buf.data(), read, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            out_error = "CryptHashData failed";
            return false;
        }
    }

    DWORD hashLen = 0;
    DWORD cbHashLen = sizeof(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &cbHashLen, 0) || hashLen == 0) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        out_error = "CryptGetHashParam(HP_HASHSIZE) failed";
        return false;
    }

    std::vector<uint8_t> hash(hashLen);
    DWORD cbHash = hashLen;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        out_error = "CryptGetHashParam(HP_HASHVAL) failed";
        return false;
    }

    out_hex = ToHexLower(hash.data(), hash.size());

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return true;
}

bool ThreatFingerprint::ExtractPeHeaders(const std::wstring& path, std::vector<uint8_t>& out_bytes, std::string& out_error) {
    out_bytes.clear();
    out_error.clear();

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        out_error = "CreateFileW(open) failed";
        return false;
    }

    // Read first 4KB to get DOS header + e_lfanew.
    std::vector<uint8_t> head(4096);
    DWORD read = 0;
    if (!ReadFile(hFile, head.data(), static_cast<DWORD>(head.size()), &read, nullptr) || read < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        out_error = "ReadFile failed";
        return false;
    }

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(head.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        out_error = "Not a PE (missing MZ)";
        return false;
    }

    LONG peOff = dos->e_lfanew;
    if (peOff <= 0 || peOff > 1024 * 1024) {
        CloseHandle(hFile);
        out_error = "Invalid e_lfanew";
        return false;
    }

    // Read enough to include NT headers + section headers.
    // We'll read from 0 to peOff + 4 + FILE_HEADER + OPTIONAL_HEADER + (nSections * 40).
    // To get nSections and optional header size, we need FILE_HEADER.
    SetFilePointer(hFile, peOff, nullptr, FILE_BEGIN);

    DWORD sig = 0;
    if (!ReadFile(hFile, &sig, sizeof(sig), &read, nullptr) || read != sizeof(sig) || sig != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        out_error = "Not a PE (missing PE\\0\\0)";
        return false;
    }

    IMAGE_FILE_HEADER fh{};
    if (!ReadFile(hFile, &fh, sizeof(fh), &read, nullptr) || read != sizeof(fh)) {
        CloseHandle(hFile);
        out_error = "Read FILE_HEADER failed";
        return false;
    }

    // Optional header size is fh.SizeOfOptionalHeader.
    DWORD total = static_cast<DWORD>(peOff) + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader + (fh.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (total > 1024 * 1024) {
        CloseHandle(hFile);
        out_error = "PE header too large";
        return false;
    }

    out_bytes.resize(total);
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    DWORD got = 0;
    if (!ReadFile(hFile, out_bytes.data(), total, &got, nullptr) || got != total) {
        CloseHandle(hFile);
        out_error = "Read PE headers failed";
        out_bytes.clear();
        return false;
    }

    CloseHandle(hFile);
    return true;
}

bool ThreatFingerprint::CheckAuthenticodeSignature(const std::wstring& path,
                                                   bool& out_valid,
                                                   std::string& out_summary,
                                                   std::string& out_error) {
    out_valid = false;
    out_summary.clear();
    out_error.clear();

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fileInfo;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(nullptr, &policy, &wd);

    out_valid = (st == ERROR_SUCCESS);
    out_summary = out_valid ? "valid" : "invalid_or_unsigned";

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &wd);

    return true;
}

void ThreatFingerprint::LoadKnownBadSha256(std::vector<std::string>& out_hashes) {
    out_hashes.clear();

    // Optional: threats/blacklist.txt (one sha256 per line)
    {
        std::ifstream f("threats/blacklist.txt");
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
                if (line.size() == 64) out_hashes.push_back(line);
            }
        }
    }

    // Also load from threats/<sha256>/hashes.json if present.
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("threats\\*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            std::string name = fd.cFileName;
            if (name == "." || name == "..") continue;
            if (name.size() == 64) {
                out_hashes.push_back(name);
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }

    std::sort(out_hashes.begin(), out_hashes.end());
    out_hashes.erase(std::unique(out_hashes.begin(), out_hashes.end()), out_hashes.end());
}

bool ThreatFingerprint::IsKnownBadSha256(const std::string& sha256) {
    std::vector<std::string> hashes;
    LoadKnownBadSha256(hashes);
    return std::find(hashes.begin(), hashes.end(), sha256) != hashes.end();
}

ThreatFingerprintResult ThreatFingerprint::CaptureForPid(uint32_t pid,
                                                        const std::string& reason,
                                                        const std::string& classification,
                                                        const std::vector<std::string>& accessed_files) {
    ThreatFingerprintResult r;

    std::string err;
    std::wstring image = GetProcessImagePathW(pid, err);
    if (image.empty()) {
        r.ok = false;
        r.error = err;
        return r;
    }

    r.image_path = WideToUtf8Local(image);

    if (!ComputeFileSha256(image, r.sha256, err)) {
        r.ok = false;
        r.error = err;
        return r;
    }

    // Ensure threats/ and threats/<sha256>/
    std::wstring threatsDir = L"threats";
    EnsureDir(threatsDir, err);

    std::wstring outDirW = threatsDir + L"\\" + Utf8ToWideLocal(r.sha256);
    if (!EnsureDir(outDirW, err)) {
        r.ok = false;
        r.error = err;
        return r;
    }

    r.output_dir = "threats/" + r.sha256;

    // Write image_path.txt
    {
        std::wstring p = outDirW + L"\\image_path.txt";
        WriteAllTextUtf8(p, r.image_path + "\n", err);
    }

    // Signature
    {
        bool valid = false;
        std::string summary;
        std::string sigErr;
        if (CheckAuthenticodeSignature(image, valid, summary, sigErr)) {
            r.signature_checked = true;
            r.signature_valid = valid;
            r.signature_summary = summary;
        }
        std::wstring p = outDirW + L"\\signature.txt";
        std::ostringstream oss;
        oss << "checked=" << (r.signature_checked ? "true" : "false") << "\n";
        oss << "valid=" << (r.signature_valid ? "true" : "false") << "\n";
        oss << "summary=" << r.signature_summary << "\n";
        if (!sigErr.empty()) oss << "error=" << sigErr << "\n";
        WriteAllTextUtf8(p, oss.str(), err);
    }

    // PE headers
    {
        std::vector<uint8_t> pe;
        std::string peErr;
        if (ExtractPeHeaders(image, pe, peErr)) {
            std::wstring p = outDirW + L"\\pe_headers.bin";
            WriteAllBytes(p, pe.data(), pe.size(), err);
        } else {
            std::wstring p = outDirW + L"\\pe_headers_error.txt";
            WriteAllTextUtf8(p, peErr + "\n", err);
        }
    }

    // hashes.json (minimal)
    {
        std::wstring p = outDirW + L"\\hashes.json";
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"sha256\": \"" << r.sha256 << "\"\n";
        oss << "}\n";
        WriteAllTextUtf8(p, oss.str(), err);
    }

    // meta.json (minimal)
    {
        std::wstring p = outDirW + L"\\meta.json";
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"pid\": " << pid << ",\n";
        oss << "  \"reason\": \"" << reason << "\",\n";
        oss << "  \"classification\": \"" << classification << "\",\n";
        oss << "  \"image_path\": \"" << r.image_path << "\",\n";
        oss << "  \"accessed_files\": [";
        for (size_t i = 0; i < accessed_files.size(); ++i) {
            oss << "\"" << accessed_files[i] << "\"";
            if (i + 1 < accessed_files.size()) oss << ", ";
        }
        oss << "]\n";
        oss << "}\n";
        WriteAllTextUtf8(p, oss.str(), err);
    }

    r.ok = true;
    return r;
}

} // namespace argus
