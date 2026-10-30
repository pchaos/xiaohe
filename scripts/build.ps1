# build.ps1 - one-shot build: auto-provisions the native WireGuard
# dependencies (wireguard-go vendored module + wintun.dll) when they are
# missing, then builds the client exe and stages the local core next to it.
#
# The core is NOT downloaded: if core-bin\aether.exe exists locally it is
# copied beside the built exe, together with the pt\ helpers (psiphon /
# lyrebird) that the core needs for the chained exits.
#
# Auto-provisioning (idempotent, judged by what is already on disk):
#   - wintun.dll  -> skipped when bin\wintun.dll or core-bin\wintun.dll
#                    already exists; otherwise downloaded from wintun.net
#   - wireguard-go -> skipped when go.mod already requires
#                    golang.zx2c4.com/wireguard; otherwise go get + tidy + vendor
#
# NOTE: Windows Defender regularly quarantines freshly built, unsigned Go
# binaries here ("file contains a virus or potentially unwanted software"),
# which shows up either as a failed go build or as the output file being
# renamed to Xiaohe.exe~. Retrying usually succeeds; if it never does, add
# an exclusion for this folder (admin PowerShell):
#
#   Add-MpPreference -ExclusionPath "E:\aether\bin", "E:\aether\build"
#
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$out = Join-Path $root "bin\Xiaohe.exe"

# ---------------------------------------------------------------------------
# [0/4] Auto-provision the native WireGuard dependencies
# ---------------------------------------------------------------------------
Write-Host "==> [0/4] checking native WireGuard dependencies..." -ForegroundColor Cyan

# wireguard-go: only fetched when the module is not in go.mod yet.
$needWG = -not (Select-String -Quiet -Path go.mod -Pattern "golang.zx2c4.com/wireguard")
if ($needWG) {
    # Same proxy story as setup-wireguard.ps1: these fetches need the proxy.
    $proxy = "http://127.0.0.1:10808"
    $env:HTTPS_PROXY = $proxy
    $env:HTTP_PROXY = $proxy
    $env:GOPROXY = "https://proxy.golang.org,direct"
    Write-Host "==> go.mod lacks golang.zx2c4.com/wireguard; fetching (proxy $proxy)..." -ForegroundColor Yellow
    go get golang.zx2c4.com/wireguard@latest
    if ($LASTEXITCODE -ne 0) { throw "go get wireguard failed - is the proxy up?" }
    go mod tidy
    go mod vendor
    if ($LASTEXITCODE -ne 0) { throw "go mod vendor failed" }
} else {
    Write-Host "    wireguard-go already in go.mod - skipping fetch"
}

# wintun.dll: skipped when already present anywhere next to the exe or core.
$wintunBin = Join-Path $root "bin\wintun.dll"
$wintunCore = Join-Path $root "core-bin\wintun.dll"
if (-not (Test-Path $wintunBin) -and -not (Test-Path $wintunCore)) {
    Write-Host "==> wintun.dll missing; downloading..." -ForegroundColor Yellow
    $WINTUN_VER = "0.14.1"
    $url = "https://www.wintun.net/builds/wintun-$WINTUN_VER.zip"
    $zip = Join-Path $env:TEMP "wintun-$WINTUN_VER.zip"
    # Direct first; fall back to the local proxy (same one setup-wireguard.ps1
    # uses) because wintun.net is not reachable from every network.
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    } catch {
        Write-Host "    direct download failed; retrying via proxy 127.0.0.1:10808..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $url -OutFile $zip -Proxy "http://127.0.0.1:10808" -UseBasicParsing
    }
    $tmp = Join-Path $env:TEMP "wintun-$WINTUN_VER"
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $dll = Get-ChildItem $tmp -Recurse -Filter "wintun.dll" | Select-Object -First 1
    if (-not $dll) { throw "wintun.dll not found in the archive" }
    New-Item -ItemType Directory -Force -Path (Join-Path $root "core-bin") | Out-Null
    Copy-Item $dll.FullName $wintunCore -Force
    Write-Host "    wintun.dll $WINTUN_VER downloaded -> core-bin\wintun.dll"
} else {
    Write-Host "    wintun.dll already present - skipping download"
}
# Defender renames a quarantined file instead of deleting it; those leftovers
# would silently keep an old binary on disk. (On a fresh checkout bin\ may not
# exist yet - create it first so the probe below does not trip -ErrorAction Stop.)
New-Item -ItemType Directory -Force -Path (Join-Path $root "bin") | Out-Null
Get-ChildItem (Join-Path $root "bin") -Filter "*.exe~" -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "==> removing $($_.Name) (left by the antivirus)"; Remove-Item $_.FullName -Force }

Write-Host "==> building Xiaohe.exe..."
$built = $false
for ($i = 1; $i -le 3 -and -not $built; $i++) {
    go build -tags wgtun -ldflags "-H windowsgui -s -w" -o $out .\cmd\aethergui
    if ($LASTEXITCODE -eq 0 -and (Test-Path $out)) {
        $built = $true
        break
    }
    Write-Host "==> attempt ${i} was blocked (usually the antivirus); retrying..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}
if (-not $built) {
    Write-Host ""
    Write-Host "The build stayed blocked. Windows Defender is almost always the" -ForegroundColor Red
    Write-Host "reason - it treats unsigned Go binaries (and the bundled psiphon"
    Write-Host "helper) as suspicious. Either allow the detection in Windows"
    Write-Host "Security, or add an exclusion in an administrator PowerShell:"
    Write-Host ""
    Write-Host "  Add-MpPreference -ExclusionPath `"$root\bin`", `"`$env:TEMP\go-build*`"" -ForegroundColor Cyan
    throw "build failed"
}

$core = Join-Path $root "core-bin\aether.exe"
if (Test-Path $core) {
    Write-Host "==> staging the local core beside the exe..."
    New-Item -ItemType Directory -Force -Path bin\core-bin | Out-Null
    Copy-Item $core bin\core-bin\aether.exe -Force
    & bin\core-bin\aether.exe --version
} else {
    Write-Warning "no local core in core-bin\ - the GUI will search beside the exe / PATH, or set the path in Settings"
}

# Make sure the DLL the native backend loads at runtime sits NEXT TO the exe.
# Step [0/4] already downloaded it into core-bin\; mirror that same file to
# bin\ (and vice versa: a bin\wintun.dll from an older setup run is copied
# into core-bin\ so the release packaging finds it there too).
if (-not (Test-Path $wintunBin) -and (Test-Path $wintunCore)) {
    Copy-Item $wintunCore $wintunBin -Force
    Write-Host "==> wintun.dll mirrored next to Xiaohe.exe"
} elseif (-not (Test-Path $wintunCore) -and (Test-Path $wintunBin)) {
    Copy-Item $wintunBin $wintunCore -Force
    Write-Host "==> wintun.dll mirrored into core-bin\"
} elseif (-not (Test-Path $wintunBin) -and -not (Test-Path $wintunCore)) {
    Write-Warning "no wintun.dll anywhere - native WireGuard will not work; re-run this script with the network up"
}

# The core looks for psiphon-tunnel-core.exe / lyrebird.exe in its own
# directory and in pt\ next to it. Without them the Psiphon and Tor exits
# cannot start.
$pt = Join-Path $root "core-bin\pt"
if (Test-Path $pt) {
    Write-Host "==> staging pt\ helpers (psiphon, lyrebird)..."
    New-Item -ItemType Directory -Force -Path bin\core-bin\pt | Out-Null
    Copy-Item (Join-Path $pt "*") bin\core-bin\pt -Recurse -Force
} else {
    Write-Warning "no core-bin\pt\ - the Psiphon and Tor exits cannot start"
}

Write-Host "==> done: bin\Xiaohe.exe"
Get-Item $out | Select-Object FullName, Length | Format-List
