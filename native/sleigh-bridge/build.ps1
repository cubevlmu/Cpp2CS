param([int]$Jobs = 8)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$cache = Join-Path $repo '.cpp2cs'

function Invoke-Checked([string]$Tool, [string[]]$Arguments) {
    & $Tool @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Tool 失败：退出码 $LASTEXITCODE" }
}

function Get-PinnedSource([string]$Name, [string]$Url, [string]$Revision) {
    $path = Join-Path $cache $Name
    if (-not (Test-Path -LiteralPath $path)) {
        Invoke-Checked git @('init', $path)
        Invoke-Checked git @('-C', $path, 'fetch', '--depth', '1', $Url, $Revision)
        Invoke-Checked git @('-C', $path, 'checkout', '--detach', 'FETCH_HEAD')
    }
    $actual = & git -C $path rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $actual -ne $Revision) { throw "$Name 版本不匹配，请检查 $path" }
    return $path
}

New-Item -ItemType Directory -Force $cache | Out-Null
# 原生库和处理器规格使用同一份固定版本源码。
$zlib = Get-PinnedSource 'zlib' 'https://github.com/madler/zlib.git' '51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf'
$sleigh = Get-PinnedSource 'sleigh' 'https://github.com/lifting-bits/sleigh.git' '5bf82bc35a41f0429caab5d45dfc50f3841bb004'
$zbuild = Join-Path $zlib 'build'
$zinstall = Join-Path $zlib 'install'
Invoke-Checked cmake @('-S', $zlib, '-B', $zbuild, '-DZLIB_BUILD_EXAMPLES=OFF', "-DCMAKE_INSTALL_PREFIX=$zinstall",
    "-DINSTALL_BIN_DIR=$zinstall/bin", "-DINSTALL_LIB_DIR=$zinstall/lib", "-DINSTALL_INC_DIR=$zinstall/include",
    "-DINSTALL_MAN_DIR=$zinstall/share/man", "-DINSTALL_PKGCONFIG_DIR=$zinstall/share/pkgconfig")
Invoke-Checked cmake @('--build', $zbuild, '--config', 'Release', '--parallel', "$Jobs")
Invoke-Checked cmake @('--install', $zbuild, '--config', 'Release', '--prefix', $zinstall)
$zlibrary = Join-Path $zinstall 'lib/zlibstatic.lib'
$zinclude = Join-Path $zinstall 'include'
$sbuild = Join-Path $sleigh 'build'
$sinstall = Join-Path $sleigh 'install'
Invoke-Checked cmake @('-S', $sleigh, '-B', $sbuild, '-Dsleigh_RELEASE_TYPE=stable', '-Dsleigh_BUILD_EXTRATOOLS=OFF', '-DFETCHCONTENT_UPDATES_DISCONNECTED=ON', "-DZLIB_LIBRARY=$zlibrary", "-DZLIB_INCLUDE_DIR=$zinclude")
Invoke-Checked cmake @('--build', $sbuild, '--config', 'Release', '--parallel', "$Jobs")
Invoke-Checked cmake @('--install', $sbuild, '--config', 'Release', '--prefix', $sinstall)
$bridge = Join-Path $cache 'build/sleighbridge'
Invoke-Checked cmake @('-S', $PSScriptRoot, '-B', $bridge, "-DCMAKE_PREFIX_PATH=$sinstall", "-DZLIB_LIBRARY=$zlibrary", "-DZLIB_INCLUDE_DIR=$zinclude")
Invoke-Checked cmake @('--build', $bridge, '--config', 'Release', '--parallel', "$Jobs")
Write-Host ('桥 DLL：' + (Join-Path $bridge 'Release/cpp2cs_sleigh_bridge.dll'))
Write-Host ('处理器规格：' + (Join-Path $sinstall 'share/sleigh/specfiles/Ghidra/Processors/x86/data/languages/x86-64.sla'))
