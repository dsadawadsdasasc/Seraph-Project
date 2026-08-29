$path = "C:\Program Files (x86)\Steam\steamapps\common\Marathon\Marathon.exe"
if (-not (Test-Path $path)) {
    Write-Host "Marathon.exe not found at: $path"
    # Try alternative paths
    $alts = @(
        "C:\Program Files\Steam\steamapps\common\Marathon\Marathon.exe",
        "D:\Steam\steamapps\common\Marathon\Marathon.exe",
        "D:\SteamLibrary\steamapps\common\Marathon\Marathon.exe",
        "C:\Program Files (x86)\Steam\steamapps\common\Marathon\Marathon-Win64-Shipping.exe"
    )
    foreach ($a in $alts) {
        if (Test-Path $a) { $path = $a; Write-Host "Found at: $path"; break }
    }
}

if (-not (Test-Path $path)) {
    Write-Host "Could not locate Marathon.exe. Searching..."
    $found = Get-ChildItem -Path "C:\","D:\" -Recurse -Filter "Marathon*.exe" -ErrorAction SilentlyContinue | Select-Object -First 5
    $found | ForEach-Object { Write-Host "  Found: $($_.FullName)" }
    exit
}

$bytes = [System.IO.File]::ReadAllBytes($path)
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$numSec = [BitConverter]::ToInt16($bytes, $e_lfanew + 6)
$optSize = [BitConverter]::ToInt16($bytes, $e_lfanew + 20)
$secBase = $e_lfanew + 24 + $optSize

Write-Host "PE: e_lfanew=0x$($e_lfanew.ToString('X')), numSections=$numSec, optSize=0x$($optSize.ToString('X'))"
Write-Host ("=" * 70)
Write-Host ("{0,-10} {1,-12} {2,-12} {3,-12} {4,-8} {5,-8}" -f "Name","VSize","RVA","Chars","Write","Exec")
Write-Host ("-" * 70)

for ($i = 0; $i -lt $numSec; $i++) {
    $off = $secBase + $i * 40
    $nameBytes = $bytes[$off..($off+7)]
    $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
    $vsize = [BitConverter]::ToUInt32($bytes, $off + 8)
    $rva   = [BitConverter]::ToUInt32($bytes, $off + 12)
    $chars = [BitConverter]::ToUInt32($bytes, $off + 36)
    $writable   = ($chars -band 0x80000000) -ne 0
    $executable = ($chars -band 0x20000000) -ne 0
    Write-Host ("{0,-10} 0x{1,-10} 0x{2,-10} 0x{3,-10} {4,-8} {5,-8}" -f $name, $vsize.ToString('X'), $rva.ToString('X'), $chars.ToString('X'), $writable, $executable)
}
