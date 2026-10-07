[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VSIX,
    [Parameter(Mandatory)][string]$Signature,
    [string]$PreviousVSIX,
    [string]$PreviousSignature,
    [string]$SandboxTrust,
    [string]$SandboxReport,
    [string]$PreviousSandboxReport,
    [string]$PublisherPolicy,
    [string]$PublisherReport,
    [string]$PreviousPublisherReport,
    [ValidateSet('verified','allowlist','any')][string]$PublisherMode = 'verified',
    [switch]$LegacyEmptySignatures,
    [string]$Binary = (Join-Path $PSScriptRoot '..\bin\code-marketplace.exe'),
    [string]$VSCodeDirectory = (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code')
)

$ErrorActionPreference = 'Stop'
foreach ($inputPath in @($VSIX, $Signature, $Binary)) {
    if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { throw "File not found: $inputPath" }
}
if ([bool]$PreviousVSIX -ne [bool]$PreviousSignature) { throw 'Provide both previous package and previous signature' }
if ([bool]$SandboxTrust -ne [bool]$SandboxReport) { throw 'Provide both sandbox trust configuration and report' }
if ($SandboxTrust -and $PreviousVSIX -and -not $PreviousSandboxReport) { throw 'Provide a sandbox report for the previous package' }
if ([bool]$PublisherPolicy -ne [bool]$PublisherReport) { throw 'Provide both publisher policy and report' }
if ($PublisherPolicy -and -not $SandboxTrust) { throw 'Publisher provenance integration tests require sandbox-gated imports' }
if ($PublisherPolicy -and $PreviousVSIX -and -not $PreviousPublisherReport) { throw 'Provide publisher provenance for the previous package' }
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$testRoot = Join-Path $env:TEMP ('code-marketplace-vscode-' + [guid]::NewGuid().ToString('N'))
$isolatedCode = Join-Path $testRoot 'vscode'
$store = Join-Path $testRoot 'marketplace'
New-Item -ItemType Directory -Path $testRoot | Out-Null
Write-Output "Evidence directory: $testRoot"
robocopy $VSCodeDirectory $isolatedCode /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'Could not create an isolated VS Code copy' }
$productPaths = @(Join-Path $isolatedCode 'resources\app\product.json')
foreach ($directory in Get-ChildItem -LiteralPath $isolatedCode -Directory) {
    $productPaths += Join-Path $directory.FullName 'resources\app\product.json'
}
$productPath = $productPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $productPath) { throw 'VS Code product.json was not found in the isolated copy' }
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$baseURL = "http://127.0.0.1:$port"
$product = Get-Content -Raw -LiteralPath $productPath | ConvertFrom-Json
$product.extensionsGallery = @{
    serviceUrl = "$baseURL/api"
    itemUrl = "$baseURL/item"
    resourceUrlTemplate = "$baseURL/files/{publisher}/{name}/{version}/{path}"
    extensionUrlTemplate = "$baseURL/api/vscode/{publisher}/{name}/latest"
}
[System.IO.File]::WriteAllText($productPath, ($product | ConvertTo-Json -Depth 100), [System.Text.UTF8Encoding]::new($false))
$code = Join-Path $isolatedCode 'bin\code.cmd'
& $code --version
if ($LASTEXITCODE -ne 0) { throw 'Isolated VS Code did not start' }

function Import-Package([string]$package, [string]$signatureFile, [string]$sandboxFile, [string]$publisherFile) {
    $incoming = Join-Path $testRoot ('incoming-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $incoming | Out-Null
    Copy-Item -LiteralPath $package -Destination (Join-Path $incoming 'package.vsix')
    Copy-Item -LiteralPath $signatureFile -Destination (Join-Path $incoming 'package.sigzip')
    if ($SandboxTrust) {
        Copy-Item -LiteralPath $sandboxFile -Destination (Join-Path $incoming 'package.sandbox.json')
        if ($PublisherPolicy) {
            Copy-Item -LiteralPath $publisherFile -Destination (Join-Path $incoming 'package.publisher.json')
            & $Binary import --incoming-dir $incoming --extensions-dir $store --sandbox-trust $SandboxTrust --publisher-mode $PublisherMode --publisher-policy $PublisherPolicy
        } else {
            & $Binary import --incoming-dir $incoming --extensions-dir $store --sandbox-trust $SandboxTrust --publisher-mode any
        }
    } else {
        & $Binary add $incoming --require-signature --extensions-dir $store
    }
    if ($LASTEXITCODE -ne 0) { throw 'Package import failed' }
}

function Invoke-CodeTest([string]$name, [string[]]$arguments, [bool]$expectSuccess = $true) {
    $profile = Join-Path $testRoot "profile-$name"
    $extensions = Join-Path $testRoot "extensions-$name"
    New-Item -ItemType Directory -Path (Join-Path $profile 'User') -Force | Out-Null
    $settings = @{
        'extensions.verifySignature' = $true
        'extensions.autoUpdate' = $false
        'extensions.autoCheckUpdates' = $false
        'telemetry.telemetryLevel' = 'off'
        'update.mode' = 'none'
        'workbench.enableExperiments' = $false
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText((Join-Path $profile 'User\settings.json'), $settings, [System.Text.UTF8Encoding]::new($false))
    $output = & $code --user-data-dir $profile --extensions-dir $extensions --log trace @arguments 2>&1
    $result = $LASTEXITCODE
    $output | Add-Content -LiteralPath (Join-Path $testRoot "$name.txt")
    $output | Where-Object { "$_" -match 'signature verification result|successfully installed|^Updating extensions|^Error while installing|^Failed Installing' } | Write-Output
    if ($expectSuccess -and $result -ne 0) { throw "VS Code test failed: $name" }
    if (-not $expectSuccess -and $result -eq 0) { throw "VS Code unexpectedly accepted tampered package: $name" }
    if ($expectSuccess -and -not (($output -join "`n") -match 'signature verification result[^\r\n]*Success[^\r\n]*Executed: true')) { throw "VS Code did not execute successful signature verification: $name" }
    if (-not $expectSuccess -and -not (($output -join "`n") -match 'SignatureVerificationFailed|Signature verification failed|PackageIntegrityCheckFailed|SignatureIntegrityCheckFailed')) { throw 'Tampered package failed before signature verification; the negative test is inconclusive' }
}

if ($PreviousVSIX) { Import-Package $PreviousVSIX $PreviousSignature $PreviousSandboxReport $PreviousPublisherReport } else { Import-Package $VSIX $Signature $SandboxReport $PublisherReport }
$serverArguments = @('server','--extensions-dir',('"' + $store + '"'),'--address',"127.0.0.1:$port",'--list-cache-duration','0s','--verbose')
if ($LegacyEmptySignatures) { $serverArguments += '--sign' }
$server = Start-Process -FilePath $Binary -ArgumentList $serverArguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testRoot 'server.stdout') -RedirectStandardError (Join-Path $testRoot 'server.stderr')
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { Invoke-RestMethod -Uri "$baseURL/healthz" -TimeoutSec 1 | Out-Null; $ready = $true; break } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $ready) { throw 'Marketplace did not become ready' }
    $payload = @{ filters = @(@{ criteria = @(@{filterType = 8; value = 'Microsoft.VisualStudio.Code'}); pageSize = 1 }); flags = 439 } | ConvertTo-Json -Depth 6
    $query = Invoke-RestMethod -Uri "$baseURL/api/extensionquery" -Method Post -ContentType 'application/json' -Body $payload
    $extension = $query.results[0].extensions[0]
    $extensionID = "$($extension.publisher.publisherName).$($extension.extensionName)"
    Invoke-CodeTest 'signed-install' @('--install-extension', $extensionID)
    if ($PreviousVSIX) {
        Import-Package $VSIX $Signature $SandboxReport $PublisherReport
        Invoke-CodeTest 'signed-install' @('--update-extensions')
    }
    $query = Invoke-RestMethod -Uri "$baseURL/api/extensionquery" -Method Post -ContentType 'application/json' -Body $payload
    $version = $query.results[0].extensions[0].versions[0]
    $signatureAssets = @($version.files | Where-Object assetType -eq 'Microsoft.VisualStudio.Services.VsixSignature')
    if ($signatureAssets.Count -ne 1) { throw 'Expected exactly one advertised signature asset' }
    $vsixAsset = $version.files | Where-Object assetType -eq 'Microsoft.VisualStudio.Services.VSIXPackage' | Select-Object -First 1
    $servedSignature = Join-Path $testRoot 'served.sigzip'
    $servedVSIX = Join-Path $testRoot 'served.vsix'
    Invoke-WebRequest -Uri $signatureAssets[0].source -OutFile $servedSignature
    Invoke-WebRequest -Uri $vsixAsset.source -OutFile $servedVSIX
    if ((Get-FileHash -LiteralPath $VSIX).Hash -ne (Get-FileHash -LiteralPath $servedVSIX).Hash) { throw 'VSIX bytes changed' }
    if ((Get-FileHash -LiteralPath $Signature).Hash -ne (Get-FileHash -LiteralPath $servedSignature).Hash) { throw 'Signature bytes changed' }
    $assetRelativePath = [Uri]::UnescapeDataString(([Uri]$vsixAsset.source).AbsolutePath.Substring('/files/'.Length))
    $publishedVSIX = Join-Path $store $assetRelativePath
    $originalBytes = [System.IO.File]::ReadAllBytes($publishedVSIX)
    try {
        $changedArchive = [System.IO.Compression.ZipFile]::Open($publishedVSIX, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $entry = $changedArchive.CreateEntry('signature-test-added-file.txt')
            $writer = [System.IO.StreamWriter]::new($entry.Open())
            try { $writer.Write('tampered package') } finally { $writer.Dispose() }
        } finally { $changedArchive.Dispose() }
        Invoke-CodeTest 'tampered-rejected' @('--install-extension', $extensionID) $false
    } finally { [System.IO.File]::WriteAllBytes($publishedVSIX, $originalBytes) }
    Write-Output 'PASS: signed install, byte preservation, and tampered-package rejection'
} finally {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id }
}
