Set-Location $PSScriptRoot

$ndkBuild = 'D:\fenxiwanjian\ndk27\ndk27\build\ndk-build.cmd'
if (-not (Test-Path $ndkBuild)) {
    Write-Host '[ERROR] ndk-build not found.'
    exit 1
}

Write-Host "[INFO] Using ndk-build: $ndkBuild"

Write-Host '[INFO] Running ndk-build...'
& $ndkBuild 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] ndk-build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host '[INFO] ndk-build succeeded.'
Write-Host '[INFO] Running integrity convergence...'
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) {
    # fallback: try common Python install paths
    if (Test-Path 'C:\Program Files\Python310\python') { $python = 'C:\Program Files\Python310\python' }
    elseif (Test-Path 'C:\Python310\python') { $python = 'C:\Python310\python' }
}
if ($python) {
    & $python "$PSScriptRoot\patch_integrity.py" "$PSScriptRoot\..\libs\arm64-v8a\safe_bypass"
} else {
    Write-Host '[ERROR] Python not found, cannot patch integrity tail'
    exit 1
}
if ($LASTEXITCODE -ne 0) {
    Write-Host '[ERROR] patch_integrity.py failed.'
    exit $LASTEXITCODE
}

Write-Host '[OK] All done.'
