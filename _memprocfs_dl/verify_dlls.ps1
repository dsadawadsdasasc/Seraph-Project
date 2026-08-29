$ErrorActionPreference = 'Stop'
$dma = Join-Path (Split-Path -Parent $PSScriptRoot) 'DMA'
$required = @{
    'vmm.dll'       = 500000
    'leechcore.dll' = 100000
    'FTD3XX.dll'    = 300000
}
foreach ($name in $required.Keys) {
    $path = Join-Path $dma $name
    if (-not (Test-Path $path)) {
        Write-Host ('[ERRO] Falta DMA\' + $name)
        exit 1
    }
    $len = (Get-Item $path).Length
    $min = $required[$name]
    if ($len -lt $min) {
        Write-Host ('[ERRO] ' + $name + ' pequeno demais: ' + $len + ' bytes, min ' + $min)
        exit 1
    }
}
$v = (Get-Item (Join-Path $dma 'vmm.dll')).VersionInfo.ProductVersion
$l = (Get-Item (Join-Path $dma 'leechcore.dll')).VersionInfo.ProductVersion
Write-Host ('[DMA] Pacote OK vmm=' + $v + ' leechcore=' + $l)
