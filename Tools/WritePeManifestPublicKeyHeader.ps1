param(
    [Parameter(Mandatory = $true)]
    [string]$HeaderPath,

    [string]$PrivateKeyPath,

    [string]$Configuration
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PeManifestSigning.ps1')

$keyPath = Resolve-PeManifestPrivateKeyPath -Configuration $Configuration -PrivateKeyPath $PrivateKeyPath
$rsa = New-PeManifestRsa -PrivateKeyPath $keyPath
try {
    $publicKeyBlob = Get-PeManifestPublicKeyBlob -Rsa $rsa
    $fingerprint = Get-PeManifestPublicKeyFingerprint -PublicKeyBlob $publicKeyBlob
    Assert-PeManifestSigningKeyAllowed -Configuration $Configuration -PublicKeyFingerprint $fingerprint
    $testHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    $testSignature = New-PeManifestSignature -Rsa $rsa -Hash $testHash
    $byteInitializer = ConvertTo-CppByteInitializer -Bytes $publicKeyBlob
}
finally {
    $rsa.Dispose()
}

$directory = Split-Path -Parent $HeaderPath
if (![string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

$content = @"
#pragma once

namespace PeIntegrity
{
static const BYTE kManifestPublicKeyBlob[] = {
$byteInitializer
};

static const char kManifestPublicKeySha256Hex[] = "$fingerprint";
static const char kManifestSignatureTestHash[] = "$testHash";
static const char kManifestSignatureTestSignature[] = "$testSignature";
}
"@

Set-Content -LiteralPath $HeaderPath -Value $content -Encoding ascii
