param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [string]$PrivateKeyPath,

    [string]$PublicKeyHeaderPath,

    [string]$Configuration
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PeManifestSigning.ps1')

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TargetPath).Hash.ToLowerInvariant()
$keyPath = Resolve-PeManifestPrivateKeyPath -Configuration $Configuration -PrivateKeyPath $PrivateKeyPath

$rsa = New-PeManifestRsa -PrivateKeyPath $keyPath
try {
    $publicKeyBlob = Get-PeManifestPublicKeyBlob -Rsa $rsa
    $fingerprint = Get-PeManifestPublicKeyFingerprint -PublicKeyBlob $publicKeyBlob
    Assert-PeManifestSigningKeyAllowed -Configuration $Configuration -PublicKeyFingerprint $fingerprint
    Assert-PeManifestPublicKeyHeaderMatches -PublicKeyHeaderPath $PublicKeyHeaderPath -ExpectedFingerprint $fingerprint
    $signature = New-PeManifestSignature -Rsa $rsa -Hash $hash
}
finally {
    $rsa.Dispose()
}

Set-Content -LiteralPath $ManifestPath -Value @($script:ManifestMagic, $hash, $signature) -Encoding ascii
