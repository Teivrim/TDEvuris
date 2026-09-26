#include "hasher.h"
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

std::string Hasher::sha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open())
        return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return {};

    DWORD hashLen = 0;
    DWORD tmp = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &tmp, 0);

    std::vector<BYTE> hash(hashLen);

    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<char> buf(65536);
    while (file) {
        file.read(buf.data(), buf.size());
        auto bytes = static_cast<ULONG>(file.gcount());
        if (bytes > 0) {
            BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buf.data()), bytes, 0);
        }
    }
    file.close();

    if (!NT_SUCCESS(BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (BYTE b : hash)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

std::string Hasher::sha256(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return {};

    DWORD hashLen = 0;
    DWORD tmp = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &tmp, 0);

    std::vector<BYTE> hash(hashLen);

    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);

    if (!NT_SUCCESS(BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (BYTE b : hash)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}
