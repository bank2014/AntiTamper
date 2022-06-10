$script:ManifestMagic = 'ATPE/1'
$script:DevelopmentKeyPath = Join-Path $PSScriptRoot 'PeManifestSigningKey.Development.xml'
$script:DevelopmentPublicKeySha256Hex = '93cda14a2fc58601bcd9b79b92671931cb58dd5164ac92b06bfb6d0195998560'

function ConvertTo-HexString([byte[]]$Bytes) {
    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Resolve-PeManifestPrivateKeyPath {
    param(
        [string]$Configuration,
        [string]$PrivateKeyPath
    )

    $normalizedConfiguration = if ([string]::IsNullOrWhiteSpace($Configuration)) { 'Debug' } else { $Configuration.Trim() }
    $isRelease = $normalizedConfiguration -ieq 'Release'

    if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
        $PrivateKeyPath = $env:ANTITAMPER_PE_SIGNING_KEY_PATH
    }

    if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
        if ($isRelease) {
            throw 'Release PE manifest signing requires ANTITAMPER_PE_SIGNING_KEY_PATH or -PrivateKeyPath.'
        }

        $PrivateKeyPath = $script:DevelopmentKeyPath
    }

    $resolvedPath = [IO.Path]::GetFullPath($PrivateKeyPath)
    $developmentPath = [IO.Path]::GetFullPath($script:DevelopmentKeyPath)

    if ($isRelease -and $resolvedPath -ieq $developmentPath) {
        throw 'Release PE manifest signing cannot use Tools\PeManifestSigningKey.Development.xml.'
    }

    if (!(Test-Path -LiteralPath $resolvedPath)) {
        throw "PE manifest private signing key was not found: $resolvedPath"
    }

    return $resolvedPath
}

function New-PeManifestRsa {
    param([Parameter(Mandatory = $true)][string]$PrivateKeyPath)

    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    $rsa.PersistKeyInCsp = $false
    $rsa.FromXmlString([IO.File]::ReadAllText($PrivateKeyPath))
    return $rsa
}

function Get-PeManifestPublicKeyBlob {
    param([Parameter(Mandatory = $true)]$Rsa)

    $parameters = $Rsa.ExportParameters($false)
    $modulus = [byte[]]$parameters.Modulus
    $exponent = [byte[]]$parameters.Exponent

    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    $bytes.AddRange([BitConverter]::GetBytes([uint32]0x31415352))
    $bytes.AddRange([BitConverter]::GetBytes([uint32]($modulus.Length * 8)))
    $bytes.AddRange([BitConverter]::GetBytes([uint32]$exponent.Length))
    $bytes.AddRange([BitConverter]::GetBytes([uint32]$modulus.Length))
    $bytes.AddRange([BitConverter]::GetBytes([uint32]0))
    $bytes.AddRange([BitConverter]::GetBytes([uint32]0))
    $bytes.AddRange($exponent)
    $bytes.AddRange($modulus)
    return $bytes.ToArray()
}

function Get-PeManifestPublicKeyFingerprint {
    param([Parameter(Mandatory = $true)][byte[]]$PublicKeyBlob)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ConvertTo-HexString $sha256.ComputeHash($PublicKeyBlob)
    }
    finally {
        $sha256.Dispose()
    }
}

function Assert-PeManifestSigningKeyAllowed {
    param(
        [string]$Configuration,
        [Parameter(Mandatory = $true)][string]$PublicKeyFingerprint
    )

    if ($Configuration -ieq 'Release' -and $PublicKeyFingerprint -eq $script:DevelopmentPublicKeySha256Hex) {
        throw 'Release PE manifest signing cannot use the development public key.'
    }
}

function New-PeManifestSignature {
    param(
        [Parameter(Mandatory = $true)]$Rsa,
        [Parameter(Mandatory = $true)][string]$Hash
    )

    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes("$($script:ManifestMagic)|$Hash")
    $signatureBytes = $Rsa.SignData($payloadBytes, [System.Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
    return ConvertTo-HexString $signatureBytes
}

function ConvertTo-CppByteInitializer {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    for ($index = 0; $index -lt $Bytes.Length; $index += 12) {
        $count = [Math]::Min(12, $Bytes.Length - $index)
        $slice = $Bytes[$index..($index + $count - 1)]
        $lines.Add("`t" + (($slice | ForEach-Object { '0x{0:x2}' -f $_ }) -join ', '))
    }

    return $lines -join ",`r`n"
}

function Assert-PeManifestPublicKeyHeaderMatches {
    param(
        [string]$PublicKeyHeaderPath,
        [Parameter(Mandatory = $true)][string]$ExpectedFingerprint
    )

    if ([string]::IsNullOrWhiteSpace($PublicKeyHeaderPath)) {
        return
    }

    if (!(Test-Path -LiteralPath $PublicKeyHeaderPath)) {
        throw "Generated public key header was not found: $PublicKeyHeaderPath"
    }

    $headerText = [IO.File]::ReadAllText($PublicKeyHeaderPath)
    $match = [regex]::Match($headerText, 'kManifestPublicKeySha256Hex\[\]\s*=\s*"([0-9a-f]{64})"')
    if (!$match.Success) {
        throw "Generated public key header is missing kManifestPublicKeySha256Hex: $PublicKeyHeaderPath"
    }

    if ($match.Groups[1].Value -ne $ExpectedFingerprint) {
        throw 'PE manifest signing key does not match the generated public key header.'
    }
}
