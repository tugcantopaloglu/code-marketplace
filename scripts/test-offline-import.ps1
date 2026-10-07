[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VSIX,
    [Parameter(Mandatory)][string]$Signature,
    [string]$Binary = (Join-Path $PSScriptRoot '..\bin\code-marketplace-next.exe')
)

$ErrorActionPreference = 'Stop'
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$testRoot = Join-Path $env:TEMP ('code-marketplace-offline-' + [guid]::NewGuid().ToString('N'))
$incoming = Join-Path $testRoot 'incoming'
$published = Join-Path $testRoot 'published'
$reports = Join-Path $testRoot 'reports'
New-Item -ItemType Directory -Path $incoming,$published | Out-Null
Copy-Item -LiteralPath $VSIX -Destination (Join-Path $incoming 'approved.vsix')
Copy-Item -LiteralPath $Signature -Destination (Join-Path $incoming 'approved.sigzip')
Copy-Item -LiteralPath $VSIX -Destination (Join-Path $incoming 'waiting.vsix')
Copy-Item -LiteralPath $VSIX -Destination (Join-Path $incoming 'incomplete.vsix.part')
& node (Join-Path $PSScriptRoot 'create-sandbox-test-report.cjs') --test-only $reports (Join-Path $incoming 'approved.vsix')
if ($LASTEXITCODE -ne 0) { throw 'Could not create test reports' }
Copy-Item -LiteralPath (Join-Path $reports 'approved.sandbox.json') -Destination $incoming
$trust = Join-Path $reports 'trust.json'
$first = & $Binary import --incoming-dir $incoming --extensions-dir $published --sandbox-trust $trust --publisher-mode any
if ($LASTEXITCODE -ne 0) { throw 'Initial import failed' }
$first | Set-Content -LiteralPath (Join-Path $testRoot 'first.json')
$results = ($first | ConvertFrom-Json).results
if (@($results | Where-Object status -eq 'imported').Count -ne 1 -or @($results | Where-Object status -eq 'waiting').Count -ne 1) { throw 'Unexpected first import results' }
$second = & $Binary import --incoming-dir $incoming --extensions-dir $published --sandbox-trust $trust --publisher-mode any
if ($LASTEXITCODE -ne 0 -or @((($second | ConvertFrom-Json).results) | Where-Object status -eq 'unchanged').Count -ne 1) { throw 'Repeated import was not idempotent' }
$second | Set-Content -LiteralPath (Join-Path $testRoot 'second.json')
$artifact = Get-ChildItem -LiteralPath $published -Recurse -File -Filter '*.vsix' | Select-Object -First 1
if ((Get-FileHash -LiteralPath $artifact.FullName).Hash -ne (Get-FileHash -LiteralPath $VSIX).Hash) { throw 'Published package bytes changed' }
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$arguments = @('server','--extensions-dir',('"' + $published + '"'),'--address',"127.0.0.1:$port",'--list-cache-duration','0s')
for ($cycle = 1; $cycle -le 2; $cycle++) {
    $process = Start-Process -FilePath $Binary -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testRoot "server-$cycle.stdout") -RedirectStandardError (Join-Path $testRoot "server-$cycle.stderr")
    try {
        $ready = $false
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            try { $null = Invoke-RestMethod "http://127.0.0.1:$port/readyz"; $ready = $true; break } catch { Start-Sleep -Milliseconds 100 }
        }
        if (-not $ready) { throw 'Marketplace did not become ready' }
        $body = @{filters=@(@{criteria=@(@{filterType=8;value='Microsoft.VisualStudio.Code'});pageSize=10});flags=439} | ConvertTo-Json -Depth 10
        $response = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/api/extensionquery" -ContentType application/json -Body $body
        $extension = $response.results[0].extensions[0]
        if (-not $extension) { throw 'Published package missing after restart' }
        $signatureAsset = @($extension.versions[0].files | Where-Object assetType -eq 'Microsoft.VisualStudio.Services.VsixSignature')
        if ($signatureAsset.Count -ne 1) { throw 'Signature asset missing after restart' }
        $download = Join-Path $testRoot "signature-$cycle.sigzip"
        Invoke-WebRequest -Uri $signatureAsset[0].source -OutFile $download
        if ((Get-FileHash -LiteralPath $download).Hash -ne (Get-FileHash -LiteralPath $Signature).Hash) { throw 'Signature changed after restart' }
        $relative = $artifact.FullName.Substring($published.Length + 1).Replace('\','/')
        $directory = $relative.Substring(0,$relative.LastIndexOf('/'))
        try {
            $null = Invoke-WebRequest "http://127.0.0.1:$port/files/$directory/.import-receipt.json"
            throw 'Import receipt was publicly readable'
        } catch {
            if ([int]$_.Exception.Response.StatusCode -ne 404) { throw }
        }
    } finally {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    }
}
Write-Output "Evidence directory: $testRoot"
Write-Output 'PASS: sandbox-gated offline import, repeated import, asset preservation, private receipts, and restart persistence'
