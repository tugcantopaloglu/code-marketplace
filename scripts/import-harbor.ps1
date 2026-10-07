param(
    [Parameter(Mandatory)][string]$BundleDirectory,
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][string]$Tag
)

$ErrorActionPreference = 'Stop'
$taskBundlePath = (Resolve-Path -LiteralPath $BundleDirectory).Path
if ($Repository -notmatch '^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*$' -or $Repository.Contains('..') -or $Repository.EndsWith('/')) { throw 'Use a Harbor repository such as harbor.internal/development/code-marketplace' }
if ($Tag -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$') { throw 'Invalid image tag' }
$taskRequired = @('image.tar.gz','image-id.txt','image-reference.txt','source-revision.txt','source.tar.gz')
$taskVerified = @{}
foreach ($taskLine in Get-Content -LiteralPath (Join-Path $taskBundlePath 'SHA256SUMS')) {
    if ($taskLine -notmatch '^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$') { throw 'Invalid checksum manifest' }
    $taskExpected, $taskFilename = $Matches[1], $Matches[2]
    if ($taskVerified.ContainsKey($taskFilename)) { throw 'Duplicate checksum entry' }
    $taskFilePath = Join-Path $taskBundlePath $taskFilename
    if ((Get-FileHash -LiteralPath $taskFilePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskExpected) { throw "Checksum mismatch: $taskFilename" }
    $taskVerified[$taskFilename] = $true
}
foreach ($taskFilename in $taskRequired) { if (!$taskVerified.ContainsKey($taskFilename)) { throw "Missing checksum entry: $taskFilename" } }
$taskSourceImage = (Get-Content -Raw -LiteralPath (Join-Path $taskBundlePath 'image-reference.txt')).Trim()
$taskExpectedID = (Get-Content -Raw -LiteralPath (Join-Path $taskBundlePath 'image-id.txt')).Trim()
if ($taskSourceImage -notmatch '^code-marketplace:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$' -or $taskExpectedID -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Invalid image metadata' }
& docker load --input (Join-Path $taskBundlePath 'image.tar.gz')
if ($LASTEXITCODE -ne 0) { throw 'Docker load failed' }
$taskActualID = & docker image inspect $taskSourceImage --format '{{.Id}}'
if ($LASTEXITCODE -ne 0 -or $taskActualID.Trim() -ne $taskExpectedID) { throw 'Loaded image does not match the bundle image ID' }
$taskTargetImage = "${Repository}:${Tag}"
& docker tag $taskSourceImage $taskTargetImage
if ($LASTEXITCODE -ne 0) { throw 'Docker tag failed' }
& docker push $taskTargetImage
if ($LASTEXITCODE -ne 0) { throw 'Harbor push failed; check docker login and the Harbor CA trust' }
Write-Output "Pushed $taskTargetImage"
