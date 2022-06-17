$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$target = Join-Path $root 'Tools\PeManifestSigningKey.Development.xml'
$manifest = Join-Path $root 'Temp\WritePeManifest.Tests.manifest.txt'
$header = Join-Path $root 'Temp\WritePeManifest.Tests.generated.h'
$mismatchKey = Join-Path $root 'Temp\WritePeManifest.Tests.mismatch.xml'
$copiedDevelopmentKey = Join-Path $root 'Temp\WritePeManifest.Tests.development-copy.xml'

New-Item -ItemType Directory -Force -Path (Join-Path $root 'Temp') | Out-Null
Remove-Item -LiteralPath $manifest, $header, $mismatchKey, $copiedDevelopmentKey -Force -ErrorAction SilentlyContinue
Remove-Item Env:\ANTITAMPER_PE_SIGNING_KEY_PATH -ErrorAction SilentlyContinue

function Assert($condition, $message) {
    if (-not $condition) {
        throw $message
    }
}

function Invoke-ExpectFailure([scriptblock]$Command, [string]$ExpectedText) {
    try {
        & $Command
    }
    catch {
        Assert ($_.Exception.Message -like "*$ExpectedText*") "Expected failure containing '$ExpectedText', got '$($_.Exception.Message)'"
        return
    }

    throw "Expected command to fail with '$ExpectedText'"
}

Invoke-ExpectFailure {
    & (Join-Path $root 'Tools\WritePeManifest.ps1') `
        -TargetPath $target `
        -ManifestPath $manifest `
        -Configuration Release
} 'Release PE manifest signing requires ANTITAMPER_PE_SIGNING_KEY_PATH'

Copy-Item -LiteralPath (Join-Path $root 'Tools\PeManifestSigningKey.Development.xml') -Destination $copiedDevelopmentKey
$env:ANTITAMPER_PE_SIGNING_KEY_PATH = $copiedDevelopmentKey
Invoke-ExpectFailure {
    & (Join-Path $root 'Tools\WritePeManifestPublicKeyHeader.ps1') `
        -HeaderPath $header `
        -Configuration Release
} 'Release PE manifest signing cannot use the development public key'
Remove-Item Env:\ANTITAMPER_PE_SIGNING_KEY_PATH -ErrorAction SilentlyContinue

& (Join-Path $root 'Tools\WritePeManifest.ps1') `
    -TargetPath $target `
    -ManifestPath $manifest `
    -Configuration Debug
Assert (Test-Path -LiteralPath $manifest) 'Debug manifest should be generated with the development key fallback'

& (Join-Path $root 'Tools\WritePeManifestPublicKeyHeader.ps1') `
    -HeaderPath $header `
    -Configuration Debug
$headerText = Get-Content -Raw -LiteralPath $header
Assert ($headerText -like '*kManifestPublicKeyBlob*') 'Generated public key header should contain the public key blob'

$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
try {
    $rsa.PersistKeyInCsp = $false
    [IO.File]::WriteAllText($mismatchKey, $rsa.ToXmlString($true))
}
finally {
    $rsa.Dispose()
}

$env:ANTITAMPER_PE_SIGNING_KEY_PATH = $mismatchKey
Invoke-ExpectFailure {
    & (Join-Path $root 'Tools\WritePeManifest.ps1') `
        -TargetPath $target `
        -ManifestPath $manifest `
        -PublicKeyHeaderPath $header `
        -Configuration Release
} 'does not match the generated public key header'

& (Join-Path $root 'Tools\WritePeManifestPublicKeyHeader.ps1') `
    -HeaderPath $header `
    -Configuration Release
& (Join-Path $root 'Tools\WritePeManifest.ps1') `
    -TargetPath $target `
    -ManifestPath $manifest `
    -PublicKeyHeaderPath $header `
    -Configuration Release

Remove-Item Env:\ANTITAMPER_PE_SIGNING_KEY_PATH -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $manifest, $header, $mismatchKey, $copiedDevelopmentKey -Force -ErrorAction SilentlyContinue

Write-Host 'WritePeManifest.Tests passed'
