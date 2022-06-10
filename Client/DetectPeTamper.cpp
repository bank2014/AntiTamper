#include "pch.h"
#include "PeIntegrity.h"

#include <bcrypt.h>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace
{
	constexpr wchar_t kExpectedPeHashFile[] = L"AntiTamperPeHash.txt";
	constexpr LONGLONG kMaxManifestBytes = 4096;

	bool BCryptSucceeded(NTSTATUS status)
	{
		return status >= 0;
	}

	string BytesToHex(const vector<BYTE>& bytes)
	{
		static constexpr char kHex[] = "0123456789abcdef";
		string hex;
		hex.reserve(bytes.size() * 2);
		for (BYTE byte : bytes)
		{
			hex.push_back(kHex[(byte >> 4) & 0x0f]);
			hex.push_back(kHex[byte & 0x0f]);
		}
		return hex;
	}

	wstring GetClientModuleImagePath()
	{
		return PeIntegrity::GetModulePathForAddress(reinterpret_cast<const void*>(&IsPeFileTampered));
	}

	bool ReadExpectedManifest(const wstring& path, PeIntegrity::ExpectedManifest& manifest)
	{
		HANDLE file = ::CreateFileW(
			path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		if (file == INVALID_HANDLE_VALUE)
			return false;

		LARGE_INTEGER fileSize{};
		if (!::GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > kMaxManifestBytes)
		{
			::CloseHandle(file);
			return false;
		}

		string contents(static_cast<size_t>(fileSize.QuadPart), '\0');
		DWORD bytesRead = 0;
		const BOOL read = ::ReadFile(file, &contents[0], static_cast<DWORD>(contents.size()), &bytesRead, nullptr);
		::CloseHandle(file);

		if (!read || bytesRead == 0)
			return false;

		contents.resize(bytesRead);
		return PeIntegrity::ParseManifestText(contents, manifest);
	}

	bool HashFileSha256(const wstring& path, string& hash)
	{
		HANDLE file = ::CreateFileW(
			path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		if (file == INVALID_HANDLE_VALUE)
			return false;

		BCRYPT_ALG_HANDLE algorithm = nullptr;
		BCRYPT_HASH_HANDLE hashHandle = nullptr;
		vector<BYTE> hashObject;
		vector<BYTE> hashBytes;
		bool success = false;

		do
		{
			if (!BCryptSucceeded(::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
				break;

			DWORD objectLength = 0;
			DWORD propertySize = 0;
			if (!BCryptSucceeded(::BCryptGetProperty(
				algorithm,
				BCRYPT_OBJECT_LENGTH,
				reinterpret_cast<PUCHAR>(&objectLength),
				sizeof(objectLength),
				&propertySize,
				0)))
				break;

			DWORD hashLength = 0;
			if (!BCryptSucceeded(::BCryptGetProperty(
				algorithm,
				BCRYPT_HASH_LENGTH,
				reinterpret_cast<PUCHAR>(&hashLength),
				sizeof(hashLength),
				&propertySize,
				0)))
				break;

			hashObject.resize(objectLength);
			hashBytes.resize(hashLength);

			if (!BCryptSucceeded(::BCryptCreateHash(
				algorithm,
				&hashHandle,
				hashObject.data(),
				static_cast<ULONG>(hashObject.size()),
				nullptr,
				0,
				0)))
				break;

			BYTE buffer[8192]{};
			while (true)
			{
				DWORD bytesRead = 0;
				if (!::ReadFile(file, buffer, sizeof(buffer), &bytesRead, nullptr))
					break;

				if (bytesRead == 0)
				{
					success = true;
					break;
				}

				if (!BCryptSucceeded(::BCryptHashData(hashHandle, buffer, bytesRead, 0)))
				{
					success = false;
					break;
				}
			}

			if (!success)
				break;

			if (!BCryptSucceeded(::BCryptFinishHash(
				hashHandle,
				hashBytes.data(),
				static_cast<ULONG>(hashBytes.size()),
				0)))
			{
				success = false;
				break;
			}

			hash = BytesToHex(hashBytes);
		} while (false);

		if (hashHandle != nullptr)
			::BCryptDestroyHash(hashHandle);
		if (algorithm != nullptr)
			::BCryptCloseAlgorithmProvider(algorithm, 0);
		::CloseHandle(file);

		return success;
	}

	bool IsTrustedManifest(const PeIntegrity::ExpectedManifest& manifest)
	{
		return PeIntegrity::VerifyManifestSignature(manifest.hash, manifest.signature);
	}
}

bool IsPeFileTampered()
{
	const wstring imagePath = GetClientModuleImagePath();
	if (imagePath.empty())
	{
		cout << "[client] PE integrity could not resolve Client.dll module path" << endl;
		return true;
	}

	const wstring expectedHashPath = PeIntegrity::BuildManifestPathForModule(imagePath);

	PeIntegrity::ExpectedManifest manifest;
	const bool expectedAvailable = ReadExpectedManifest(expectedHashPath, manifest);
	const bool manifestTrusted = expectedAvailable && IsTrustedManifest(manifest);

	string actualHash;
	const bool actualAvailable = HashFileSha256(imagePath, actualHash);
	const PeIntegrity::IntegrityStatus status = PeIntegrity::EvaluateIntegrity(
		expectedAvailable,
		manifest.hash,
		manifestTrusted,
		actualAvailable,
		actualHash);

	switch (status)
	{
	case PeIntegrity::IntegrityStatus::Clean:
		return false;
	case PeIntegrity::IntegrityStatus::MissingExpectedHash:
		cout << "[client] PE integrity expected hash file is missing: AntiTamperPeHash.txt" << endl;
		break;
	case PeIntegrity::IntegrityStatus::InvalidExpectedHash:
		cout << "[client] PE integrity expected hash is invalid" << endl;
		break;
	case PeIntegrity::IntegrityStatus::UntrustedManifest:
		cout << "[client] PE integrity manifest signature is invalid" << endl;
		break;
	case PeIntegrity::IntegrityStatus::HashCalculationFailed:
		cout << "[client] PE integrity hash calculation failed" << endl;
		break;
	case PeIntegrity::IntegrityStatus::Tampered:
		cout << "[client] PE file tamper detected. Expected=" << manifest.hash
			<< " Actual=" << actualHash << endl;
		break;
	}

	return true;
}
