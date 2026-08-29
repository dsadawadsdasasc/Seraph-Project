$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dlDir = $PSScriptRoot
$zip = Join-Path $dlDir 'memprocfs.zip'

# Latest release URL (stable, updated per release)
$tag = 'v5.17'
$zipName = 'MemProcFS_files_and_binaries_v5.17.8-win_x64-20260611.zip'
$url = "https://github.com/ufrisk/MemProcFS/releases/download/$tag/$zipName"

Write-Host "Downloading MemProcFS 5.17.8..."
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

$extract = Join-Path $dlDir 'extract'
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $extract -Force

# Copy DLLs to DMA\
$names = @('vmm.dll', 'leechcore.dll', 'FTD3XX.dll')
$dma = Join-Path $root 'DMA'
New-Item -ItemType Directory -Force -Path $dma | Out-Null

foreach ($name in $names) {
    $found = Get-ChildItem -Path $extract -Recurse -Filter $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { throw "Missing $name in zip" }
    $dest = Join-Path $dma $name
    Copy-Item -Path $found.FullName -Destination $dest -Force
    $vi = (Get-Item $dest).VersionInfo.ProductVersion
    $sz = (Get-Item $dest).Length
    Write-Host "OK $name v$vi ($sz bytes)"
}

# Copy headers + libs to DMA-Lib
$dmaLibBase = Join-Path $root '..\DMA-Lib-main\Teeko-DMA-Lib-main\Teeko-DMA-Lib\Teeko-DMA-Lib\Teeko-DMA'
$deps = Join-Path $dmaLibBase 'deps'
$libs = Join-Path $dmaLibBase 'libs'
New-Item -ItemType Directory -Force -Path $deps | Out-Null
New-Item -ItemType Directory -Force -Path $libs | Out-Null

$hdrNames = @('vmmdll.h', 'leechcore.h')
foreach ($h in $hdrNames) {
    $found = Get-ChildItem -Path $extract -Recurse -Filter $h -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Copy-Item -Path $found.FullName -Destination (Join-Path $deps $h) -Force
        Write-Host "OK $h -> deps"
    }
}

$libNames = @('vmm.lib', 'leechcore.lib')
foreach ($l in $libNames) {
    $found = Get-ChildItem -Path $extract -Recurse -Filter $l -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Copy-Item -Path $found.FullName -Destination (Join-Path $libs $l) -Force
        Write-Host "OK $l -> libs"
    }
}

Write-Host "Done. All DLLs, headers, and libs in place."
