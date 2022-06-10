#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#include "PeManifestPublicKey.generated.h"

namespace PeIntegrity
{
	static constexpr char kManifestMagic[] = "ATPE/1";

	enum class IntegrityStatus
	{
		Clean,
		Tampered,
		MissingExpectedHash,
		InvalidExpectedHash,
		UntrustedManifest,
		HashCalculationFailed
	};

	struct ExpectedManifest
	{
		std::string hash;
		std::string signature;
	};

	inline std::string NormalizeHash(std::string value)
	{
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
			value.erase(value.begin());
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
			value.pop_back();

		std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
			return static_cast<char>(std::tolower(ch));
		});
		return value;
	}

	inline bool IsSha256Hex(const std::string& value)
	{
		if (value.size() != 64)
			return false;

		for (char ch : value)
		{
			if (!std::isxdigit(static_cast<unsigned char>(ch)))
				return false;
		}
		return true;
	}

	inline bool ParseManifestText(const std::string& text, ExpectedManifest& manifest)
	{
		std::istringstream stream(text);
		std::string magic;
		if (!std::getline(stream, magic))
			return false;
		if (NormalizeHash(magic) != NormalizeHash(kManifestMagic))
			return false;

		if (!std::getline(stream, manifest.hash))
			return false;
		if (!std::getline(stream, manifest.signature))
			return false;

		manifest.hash = NormalizeHash(manifest.hash);
		manifest.signature = NormalizeHash(manifest.signature);
		return !manifest.hash.empty() && !manifest.signature.empty();
	}

	inline bool BCryptOk(NTSTATUS status)
	{
		return status >= 0;
	}

	inline int HexValue(char ch)
	{
		if (ch >= '0' && ch <= '9')
			return ch - '0';
		if (ch >= 'a' && ch <= 'f')
			return 10 + ch - 'a';
		if (ch >= 'A' && ch <= 'F')
			return 10 + ch - 'A';
		return -1;
	}

	inline bool HexToBytes(const std::string& hex, std::vector<BYTE>& bytes)
	{
		if (hex.empty() || hex.size() % 2 != 0)
			return false;

		bytes.clear();
		bytes.reserve(hex.size() / 2);
		for (size_t i = 0; i < hex.size(); i += 2)
		{
			const int high = HexValue(hex[i]);
			const int low = HexValue(hex[i + 1]);
			if (high < 0 || low < 0)
				return false;
			bytes.push_back(static_cast<BYTE>((high << 4) | low));
		}
		return true;
	}

	inline bool Sha256Bytes(const std::string& text, std::vector<BYTE>& hash)
	{
		BCRYPT_ALG_HANDLE algorithm = nullptr;
		BCRYPT_HASH_HANDLE hashHandle = nullptr;
		std::vector<BYTE> hashObject;
		bool success = false;

		do
		{
			if (!BCryptOk(::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
				break;

			DWORD objectLength = 0;
			DWORD propertySize = 0;
			if (!BCryptOk(::BCryptGetProperty(
				algorithm,
				BCRYPT_OBJECT_LENGTH,
				reinterpret_cast<PUCHAR>(&objectLength),
				sizeof(objectLength),
				&propertySize,
				0)))
				break;

			DWORD hashLength = 0;
			if (!BCryptOk(::BCryptGetProperty(
				algorithm,
				BCRYPT_HASH_LENGTH,
				reinterpret_cast<PUCHAR>(&hashLength),
				sizeof(hashLength),
				&propertySize,
				0)))
				break;

			hashObject.resize(objectLength);
			hash.resize(hashLength);

			if (!BCryptOk(::BCryptCreateHash(
				algorithm,
				&hashHandle,
				hashObject.data(),
				static_cast<ULONG>(hashObject.size()),
				nullptr,
				0,
				0)))
				break;

			if (!BCryptOk(::BCryptHashData(
				hashHandle,
				reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())),
				static_cast<ULONG>(text.size()),
				0)))
				break;

			if (!BCryptOk(::BCryptFinishHash(hashHandle, hash.data(), static_cast<ULONG>(hash.size()), 0)))
				break;

			success = true;
		} while (false);

		if (hashHandle != nullptr)
			::BCryptDestroyHash(hashHandle);
		if (algorithm != nullptr)
			::BCryptCloseAlgorithmProvider(algorithm, 0);

		if (!success)
			hash.clear();
		return success;
	}

	inline bool VerifyManifestSignature(const std::string& hash, const std::string& signatureHex)
	{
		const std::string normalizedHash = NormalizeHash(hash);
		if (!IsSha256Hex(normalizedHash))
			return false;

		std::vector<BYTE> signature;
		if (!HexToBytes(NormalizeHash(signatureHex), signature))
			return false;

		std::vector<BYTE> payloadHash;
		if (!Sha256Bytes(std::string(kManifestMagic) + "|" + normalizedHash, payloadHash))
			return false;

		BCRYPT_ALG_HANDLE algorithm = nullptr;
		BCRYPT_KEY_HANDLE key = nullptr;
		bool trusted = false;

		do
		{
			if (!BCryptOk(::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0)))
				break;

			if (!BCryptOk(::BCryptImportKeyPair(
				algorithm,
				nullptr,
				BCRYPT_RSAPUBLIC_BLOB,
				&key,
				const_cast<PUCHAR>(kManifestPublicKeyBlob),
				static_cast<ULONG>(sizeof(kManifestPublicKeyBlob)),
				0)))
				break;

			BCRYPT_PKCS1_PADDING_INFO paddingInfo{};
			paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
			trusted = BCryptOk(::BCryptVerifySignature(
				key,
				&paddingInfo,
				payloadHash.data(),
				static_cast<ULONG>(payloadHash.size()),
				signature.data(),
				static_cast<ULONG>(signature.size()),
				BCRYPT_PAD_PKCS1));
		} while (false);

		if (key != nullptr)
			::BCryptDestroyKey(key);
		if (algorithm != nullptr)
			::BCryptCloseAlgorithmProvider(algorithm, 0);

		return trusted;
	}

	inline std::wstring GetModulePathForAddress(const void* address)
	{
		HMODULE module = nullptr;
		if (!::GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(address),
			&module))
			return std::wstring();

		std::vector<wchar_t> path(MAX_PATH);
		while (true)
		{
			const DWORD copied = ::GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
			if (copied == 0)
				return std::wstring();
			if (copied < path.size() - 1)
				return std::wstring(path.data(), copied);
			path.resize(path.size() * 2);
		}
	}

	inline std::wstring GetDirectoryName(std::wstring path)
	{
		const size_t slash = path.find_last_of(L"\\/");
		if (slash != std::wstring::npos)
			path.erase(slash);
		return path;
	}

	inline std::wstring BuildManifestPathForModule(const std::wstring& modulePath)
	{
		return GetDirectoryName(modulePath) + L"\\AntiTamperPeHash.txt";
	}

	inline IntegrityStatus EvaluateIntegrity(
		bool expectedHashAvailable,
		const std::string& expectedHash,
		bool manifestTrusted,
		bool actualHashAvailable,
		const std::string& actualHash)
	{
		if (!expectedHashAvailable)
			return IntegrityStatus::MissingExpectedHash;

		const std::string normalizedExpected = NormalizeHash(expectedHash);
		if (!IsSha256Hex(normalizedExpected))
			return IntegrityStatus::InvalidExpectedHash;

		if (!manifestTrusted)
			return IntegrityStatus::UntrustedManifest;

		if (!actualHashAvailable)
			return IntegrityStatus::HashCalculationFailed;

		const std::string normalizedActual = NormalizeHash(actualHash);
		if (!IsSha256Hex(normalizedActual))
			return IntegrityStatus::HashCalculationFailed;

		return normalizedExpected == normalizedActual
			? IntegrityStatus::Clean
			: IntegrityStatus::Tampered;
	}

	inline bool IsTamperStatus(IntegrityStatus status)
	{
		return status != IntegrityStatus::Clean;
	}
}
