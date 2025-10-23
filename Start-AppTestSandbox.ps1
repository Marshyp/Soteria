<# 
Start-AppTestSandbox.ps1
Host-side bootstrapper for Automated Application Tester in Windows Sandbox
#>

param(
    [string]$HostOutputRoot = "C:\SandboxAppTest",
    [string]$SandboxDisplayName = "AppTest Sandbox",
    [switch]$EnableNetworking = $true
)

# Create folders
$assets = Join-Path $HostOutputRoot "Assets"
$out    = Join-Path $HostOutputRoot "Output"
New-Item -ItemType Directory -Force -Path $assets, $out | Out-Null

# --- Write the Sandbox-Runner.ps1 that executes inside the Sandbox ---
$runner = @'
# Sandbox-Runner.ps1
# Runs inside the Windows Sandbox. Prompts, downloads, checks VirusTotal, monitors, records, installs, and builds dashboard.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Toast {
    param([string]$Title, [string]$Message)
    try {
        if (-not (Get-Module -ListAvailable -Name BurntToast)) {
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction SilentlyContinue | Out-Null
            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            Install-Module BurntToast -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        }
        Import-Module BurntToast -ErrorAction Stop
        New-BurntToastNotification -Text $Title, $Message | Out-Null
    } catch {
        Write-Host "[Toast] $Title - $Message"
    }
}

# Resolve mapped folders (host drive-in)
$desktop = [Environment]::GetFolderPath("Desktop")
$hostAssets = Join-Path $desktop "Assets"
$hostOutput = Join-Path $desktop "Output"
if (-not (Test-Path $hostAssets)) { $hostAssets = "C:\Assets" }     # fallback if mapping differs
if (-not (Test-Path $hostOutput)) { $hostOutput = "C:\Output" }     # fallback if mapping differs
New-Item -ItemType Directory -Force -Path $hostOutput | Out-Null

# Working folder inside Sandbox
$work = "C:\Work"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work

# Prompt user
Add-Type -AssemblyName Microsoft.VisualBasic
$downloadUrl = [Microsoft.VisualBasic.Interaction]::InputBox("Paste the direct download URL for the installer (EXE/MSI/APPX/MSIX...)", "Installer URL", "")
if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
    Show-Toast -Title "AppTest" -Message "No URL provided. Exiting."
    exit 1
}
$vtKey = [Microsoft.VisualBasic.Interaction]::InputBox("Enter your VirusTotal API Key (optional, press OK to skip)", "VirusTotal API Key", "")
$recordMinsStr = [Microsoft.VisualBasic.Interaction]::InputBox("Recording/monitoring duration in minutes (post-install)", "Runtime Duration", "3")
if (-not [int]::TryParse($recordMinsStr, [ref]([int]$recordMins))) { $recordMins = 3 }

# Filenames/paths
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir    = Join-Path $hostOutput $timestamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$installerPath = Join-Path $work "package"
$perfCsv       = Join-Path $outDir "perf.csv"
$vtJson        = Join-Path $outDir "virustotal.json"
$vtTxt         = Join-Path $outDir "virustotal.txt"
$ffDir         = Join-Path $work "ffmpeg"
$recording     = Join-Path $outDir "screen.mp4"
$evtxAll       = Join-Path $outDir "events.evtx"
$evCsv         = Join-Path $outDir "events.csv"
$htmlDash      = Join-Path $outDir "index.html"
$msiLog        = Join-Path $outDir "msi.log"

Show-Toast -Title "AppTest" -Message "Downloading installer..."
# Download installer
try {
    $wc = New-Object System.Net.WebClient
    $fn = Split-Path -Leaf $downloadUrl
    if ([string]::IsNullOrWhiteSpace($fn)) { $fn = "installer.bin" }
    $installerPath = Join-Path $work $fn
    $wc.DownloadFile($downloadUrl, $installerPath)
} catch {
    Show-Toast -Title "AppTest" -Message "Download failed: $($_.Exception.Message)"
    throw
}

# Hash & VirusTotal lookup
Show-Toast -Title "AppTest" -Message "Hashing file..."
$sha256 = (Get-FileHash -Algorithm SHA256 -Path $installerPath).Hash
$sha1   = (Get-FileHash -Algorithm SHA1 -Path $installerPath).Hash
$md5    = (Get-FileHash -Algorithm MD5 -Path $installerPath).Hash
$hashInfo = [PSCustomObject]@{
    File       = (Split-Path -Leaf $installerPath)
    SizeBytes  = (Get-Item $installerPath).Length
    SHA256     = $sha256
    SHA1       = $sha1
    MD5        = $md5
    CheckedAt  = (Get-Date).ToString("s")
}
$hashInfo | ConvertTo-Json | Out-File -Encoding UTF8 (Join-Path $outDir "hash.json")

if ($vtKey) {
    Show-Toast -Title "AppTest" -Message "Querying VirusTotal..."
    try {
        $headers = @{ "x-apikey" = $vtKey }
        $resp = Invoke-RestMethod -Uri ("https://www.virustotal.com/api/v3/files/{0}" -f $sha256.ToLower()) -Headers $headers -Method GET -ErrorAction Stop
        $resp | ConvertTo-Json -Depth 8 | Out-File -Encoding UTF8 $vtJson
        # Brief summary
        $stats = $resp.data.attributes.last_analysis_stats
        "Detections: malicious={0}, suspicious={1}, undetected={2}, harmless={3}" -f $stats.malicious,$stats.suspicious,$stats.undetected,$stats.harmless | Out-File -Encoding UTF8 $vtTxt
    } catch {
        "VirusTotal lookup failed: $($_.Exception.Message)" | Out-File -Encoding UTF8 $vtTxt
    }
} else {
    "No VirusTotal API key provided." | Out-File -Encoding UTF8 $vtTxt
}

# Download ffmpeg (screen recording)
Show-Toast -Title "AppTest" -Message "Preparing screen recorder..."
New-Item -ItemType Directory -Force -Path $ffDir | Out-Null
try {
    # Small helper to fetch a static ffmpeg build (adjust if needed)
    $ffUrl = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-git-essentials.7z"
    $ff7z  = Join-Path $ffDir "ffmpeg.7z"
    (New-Object System.Net.WebClient).DownloadFile($ffUrl, $ff7z)
    # Expand 7z using TAR (Windows 11+ can handle .tar/.zip natively, but not .7z). Fall back to winget portable if available
    # To keep this resilient, also try a ZIP mirror:
    if (-not (Test-Path (Join-Path $ffDir "ffmpeg.exe"))) {
        try {
            $zipUrl = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-git-essentials.zip"
            $ffZip  = Join-Path $ffDir "ffmpeg.zip"
            (New-Object System.Net.WebClient).DownloadFile($zipUrl, $ffZip)
            Expand-Archive -Path $ffZip -DestinationPath $ffDir -Force
            $ffExe = Get-ChildItem -Path $ffDir -Filter "ffmpeg.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($ffExe) { Copy-Item $ffExe.FullName (Join-Path $ffDir "ffmpeg.exe") -Force }
        } catch {}
    }
} catch {}

$ffmpeg = Join-Path $ffDir "ffmpeg.exe"
if (-not (Test-Path $ffmpeg)) {
    Show-Toast -Title "AppTest" -Message "ffmpeg unavailable; fallback to PSR capture."
    $ffmpeg = $null
}

# Start performance capture
Show-Toast -Title "AppTest" -Message "Starting performance capture..."
$ctr = @(
    '\Processor(_Total)\% Processor Time',
    '\Memory\% Committed Bytes In Use',
    '\PhysicalDisk(_Total)\Disk Transfers/sec'
)
$perfJob = Start-Job -ScriptBlock {
    param($ctr, $perfCsv)
    try {
        Get-Counter -Counter $ctr -SampleInterval 1 -Continuous |
            ForEach-Object {
                foreach ($s in $_.CounterSamples) {
                    [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString('s')
                        Counter   = $s.Path
                        Value     = [math]::Round($s.CookedValue,2)
                    }
                }
            } | Export-Csv -Path $perfCsv -NoTypeInformation -Append
    } catch { }
} -ArgumentList ($ctr, $perfCsv)

# Optional screen recording start (or PSR)
$recordStopTime = (Get-Date).AddMinutes($recordMins)
if ($ffmpeg) {
    Show-Toast -Title "AppTest" -Message "Screen recording started (ffmpeg)..."
    $recArgs = @("-y","-f","gdigrab","-framerate","30","-i","desktop",$recording)
    $recProc = Start-Process -FilePath $ffmpeg -ArgumentList $recArgs -PassThru -WindowStyle Hidden
} else {
    Show-Toast -Title "AppTest" -Message "Starting Problem Steps Recorder..."
    $psrOut = Join-Path $outDir "screen.zip"
    Start-Process -FilePath "psr.exe" -ArgumentList "/start","/output",$psrOut,"/sc","1","/gui","0"
}

# Mark start time for event logs
$startTime = Get-Date

# Install logic
function Install-PackageSmart {
    param([string]$Path, [string]$MsiLogPath)

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()

    switch ($ext) {
        ".msi" {
            Show-Toast -Title "AppTest" -Message "Installing MSI..."
            # Try passive first; if failure, run interactive
            try {
                $p = Start-Process "msiexec.exe" -ArgumentList "/i `"$Path`" /L*v `"$MsiLogPath`" /passive" -Wait -PassThru
                if ($p.ExitCode -ne 0) {
                    Start-Process "msiexec.exe" -ArgumentList "/i `"$Path`" /L*v `"$MsiLogPath`"" -Wait
                }
            } catch {
                Start-Process "msiexec.exe" -ArgumentList "/i `"$Path`" /L*v `"$MsiLogPath`"" -Wait
            }
        }
        { @(".appx",".appxbundle",".msix",".msixbundle") -contains $_ } {
            Show-Toast -Title "AppTest" -Message "Installing APPX/MSIX..."
            Add-AppxPackage -Path $Path -ErrorAction SilentlyContinue
        }
        default {
            Show-Toast -Title "AppTest" -Message "Installing EXE (best-effort)..."
            # Common silent switches; if they fail, fall back to interactive
            $exeSilent = @("/S","/silent","/verysilent","/passive","/qn")
            $installed = $false
            foreach ($sw in $exeSilent) {
                try {
                    $p = Start-Process -FilePath $Path -ArgumentList $sw -Wait -PassThru -ErrorAction Stop
                    if ($p.ExitCode -eq 0) { $installed = $true; break }
                } catch { }
            }
            if (-not $installed) {
                # Interactive as last resort
                Start-Process -FilePath $Path -Wait
            }
        }
    }
}

Show-Toast -Title "AppTest" -Message "Launching installer..."
Install-PackageSmart -Path $installerPath -MsiLogPath $msiLog

# Post-install runtime observation window
Show-Toast -Title "AppTest" -Message "Observing runtime for $recordMins minute(s)..."
while ((Get-Date) -lt $recordStopTime) { Start-Sleep -Seconds 1 }

# Stop capture
Show-Toast -Title "AppTest" -Message "Stopping captures..."
try {
    if ($ffmpeg -and $recProc -and -not $recProc.HasExited) { $recProc | Stop-Process -Force }
    else {
        # Stop PSR
        Start-Process -FilePath "psr.exe" -ArgumentList "/stop" -WindowStyle Hidden
    }
} catch {}
try {
    Stop-Job $perfJob -Force | Out-Null
    Receive-Job $perfJob -ErrorAction SilentlyContinue | Out-Null
} catch {}

# Collect Event Logs for the window
$endTime = Get-Date
Show-Toast -Title "AppTest" -Message "Exporting Event Logs..."
$filters = @(
    @{LogName="Application"; ProviderName="MsiInstaller"; StartTime=$startTime; EndTime=$endTime},
    @{LogName="Microsoft-Windows-AppxDeploymentServer/Operational"; StartTime=$startTime; EndTime=$endTime},
    @{LogName="System"; StartTime=$startTime; EndTime=$endTime}
)

# Export a combined CSV
$allEvents = @()
foreach ($f in $filters) {
    try {
        $ev = Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue
        if ($ev) { $allEvents += $ev }
    } catch {}
}
$allEvents |
    Select-Object TimeCreated, LogName, ProviderName, Id, LevelDisplayName, Message |
    Export-Csv -Path $evCsv -NoTypeInformation

# Export raw EVTX (Application/System only because Operational requires direct export)
wevtutil epl Application "$($outDir)\Application.evtx" /q:"*[System[TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString("o"))' and @SystemTime<='$($endTime.ToUniversalTime().ToString("o"))']]]"
wevtutil epl System      "$($outDir)\System.evtx"      /q:"*[System[TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString("o"))' and @SystemTime<='$($endTime.ToUniversalTime().ToString("o"))']]]"
# AppX operational may not support epl range the same way; skip if fails.

# Prepare minimal dashboard (Chart.js)
Show-Toast -Title "AppTest" -Message "Building dashboard..."
$perfRows = @()
if (Test-Path $perfCsv) {
    $perfRows = Import-Csv $perfCsv
}

# Build lightweight datasets for chart.js (CPU, Memory %, IOPS)
$labels = @()
$cpu = @()
$mem = @()
$iops = @()
foreach ($g in $perfRows) {
    if (-not $labels.Contains($g.Timestamp)) { $labels += $g.Timestamp }
}

foreach ($t in $labels) {
    $cpuVal  = ($perfRows | Where-Object { $_.Timestamp -eq $t -and $_.Counter -like "*Processor(_Total)*% Processor Time" } | Select-Object -First 1).Value
    $memVal  = ($perfRows | Where-Object { $_.Timestamp -eq $t -and $_.Counter -like "*Memory*% Committed Bytes In Use" } | Select-Object -First 1).Value
    $iopsVal = ($perfRows | Where-Object { $_.Timestamp -eq $t -and $_.Counter -like "*PhysicalDisk(_Total)*Disk Transfers/sec" } | Select-Object -First 1).Value
    $cpu  += ([double]($cpuVal  ? $cpuVal  : 0))
    $mem  += ([double]($memVal  ? $memVal  : 0))
    $iops += ([double]($iopsVal ? $iopsVal : 0))
}

$hash = Get-Content (Join-Path $outDir "hash.json") -Raw
$vt   = (Test-Path $vtTxt) ? (Get-Content $vtTxt -Raw) : "No VirusTotal summary."

$downloadLinks = @()
Get-ChildItem -Path $outDir | ForEach-Object {
    $downloadLinks += "<li><a href='./$($_.Name)' download>$($_.Name)</a></li>"
}

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Automated App Test – $($hashInfo.File)</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; background: var(--bg,#0b0b0c); }
  body { background: #0b0b0c; color: #eaeaea; }
  .wrap { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.6rem; margin: 0 0 8px; }
  .sub { color: #9aa0a6; margin-bottom: 24px; }
  .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit,minmax(280px,1fr)); }
  .card { background: #121316; border: 1px solid #2a2c31; border-radius: 16px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.3); }
  .card h2 { font-size: 1.1rem; margin-top: 0; }
  video { width: 100%; border-radius: 12px; border: 1px solid #2a2c31; }
  a { color: #8ab4f8; text-decoration: none; }
  a:hover { text-decoration: underline; }
  ul { margin: 0; padding-left: 18px; }
  code { background: #1a1b1f; padding: 2px 6px; border-radius: 6px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.9rem; }
  .kvs { display:grid; grid-template-columns: 140px 1fr; gap: 8px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Automated Application Test</h1>
  <div class="sub">File: <code class="mono">${($hashInfo.File)}</code> • Size: <code class="mono">${($hashInfo.SizeBytes)} bytes</code> • SHA-256: <code class="mono">${($hashInfo.SHA256)}</code></div>

  <div class="grid">
    <div class="card">
      <h2>CPU usage (%)</h2>
      <canvas id="cpu"></canvas>
    </div>
    <div class="card">
      <h2>Memory usage (% committed)</h2>
      <canvas id="mem"></canvas>
    </div>
    <div class="card">
      <h2>IOPS (Disk Transfers/sec)</h2>
      <canvas id="iops"></canvas>
    </div>
    <div class="card">
      <h2>VirusTotal</h2>
      <pre class="mono" style="white-space:pre-wrap;">${([System.Web.HttpUtility]::HtmlEncode($vt))}</pre>
      <p><a href="./virustotal.json" download>Download raw result (JSON)</a></p>
    </div>
    <div class="card">
      <h2>Event Logs</h2>
      <p>Window: <code class="mono">${($startTime.ToString("s"))}</code> to <code class="mono">${($endTime.ToString("s"))}</code></p>
      <p><a href="./events.csv" download>Download events.csv</a></p>
      <ul>
        <li><a href="./Application.evtx" download>Application.evtx</a></li>
        <li><a href="./System.evtx" download>System.evtx</a></li>
        ${(Test-Path $msiLog) ? "<li><a href='./msi.log' download>MSI log</a></li>" : ""}
      </ul>
    </div>
    <div class="card">
      <h2>Screen Recording</h2>
      ${(Test-Path $recording) ? "<video controls src='./screen.mp4'></video><p><a href='./screen.mp4' download>Download recording</a></p>" : "<p>No MP4 available (PSR ZIP recorded). <a href='./screen.zip' download>Download PSR capture</a></p>"}
    </div>
    <div class="card">
      <h2>All Artefacts</h2>
      <ul>
        $($downloadLinks -join "`n")
      </ul>
    </div>
  </div>
</div>

<script>
const labels = @(@($labels) | ForEach-Object { "'$_'" }) -join ',';
const cpu = [@($cpu -join ',')];
const mem = [@($mem -join ',')];
const iops= [@($iops -join ',')];

function lineChart(id, label, data) {
  const ctx = document.getElementById(id);
  new Chart(ctx, {
    type: 'line',
    data: { labels: [@($labels | ForEach-Object { "'$_'" } -join ',')], datasets: [{ label, data, fill:false, tension:0.25 }] },
    options: { responsive: true, interaction: { mode:'index', intersect:false }, scales: { x: { ticks: { maxRotation: 0, autoSkip: true } } } }
  });
}

lineChart('cpu', 'CPU %', cpu);
lineChart('mem', 'Memory %', mem);
lineChart('iops','Disk Transfers/sec', iops);
</script>

</body>
</html>
"@

$html | Out-File -FilePath $htmlDash -Encoding UTF8

Show-Toast -Title "AppTest" -Message "Done. Dashboard ready."
Write-Host "Output written to: $outDir"
Write-Host "Open index.html on the HOST (mapped Output folder on your desktop)."
'@

$runnerPath = Join-Path $assets "Sandbox-Runner.ps1"
$runner | Out-File -FilePath $runnerPath -Encoding UTF8 -Force

# Compute networking mode first
$netMode = if ($EnableNetworking) { "Enable" } else { "Disable" }

# --- Create the .wsb file ---
$wsb = @"
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>$netMode</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$assets</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$out</HostFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -ExecutionPolicy Bypass -File `"%USERPROFILE%\Desktop\Assets\Sandbox-Runner.ps1`"</Command>
  </LogonCommand>
</Configuration>
"@

$wsbPath = Join-Path $HostOutputRoot "AppTest.wsb"
$wsb | Out-File -FilePath $wsbPath -Encoding UTF8 -Force

Write-Host "Launching Windows Sandbox..."
Start-Process -FilePath "C:\Windows\System32\WindowsSandbox.exe" -ArgumentList "`"$wsbPath`""
