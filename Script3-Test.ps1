<#
Soteria - Install + Test + Benchmark

Runs inside Windows Sandbox.

What it does:
 - Reads InstallerInfo.json (written by Script2-Menu.ps1)
 - Installs EXE/MSI/MSIX
 - Launches the app and captures performance metrics (Perf counters)
 - Extracts event logs related to the install window
 - Generates hashes + optional VirusTotal lookup
 - Updates a persistent history file (mapped folder)
 - Renders an HTML dashboard (with charts & a "Print to PDF" button)
 - Shuts down the sandbox

Notes:
 - EXE silent switches vary; GUI allows optional installer args.
 - VirusTotal requires an API key; leave blank to skip.
#>

Set-StrictMode -Version Latest

$Root = Join-Path $env:SystemDrive 'SandboxTest'
$InstallerInfoPath = Join-Path $Root 'InstallerInfo.json'
$Logo = Join-Path $Root 'Personalisation\icon.jpg'

# Optional: set your VirusTotal API key. If empty, VT is skipped.
$VirusTotalAPIKey = ""  # e.g. "abc123..."

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][string]$LogPath
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts - $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Ensure-BurntToast {
    try {
        if (-not (Get-Module -ListAvailable -Name BurntToast)) {
            if (-not (Get-PackageProvider -ListAvailable | Where-Object Name -eq 'NuGet')) {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
            }
            Install-Module -Name BurntToast -Force -Scope CurrentUser -ErrorAction Stop
        }
        Import-Module BurntToast -Force -ErrorAction Stop
    } catch {
        # Non-fatal (offline sandbox etc.)
    }
}

function Toast {
    param([string[]]$Text, [string]$LogoPath, [string]$Id)
    try { New-BurntToastNotification -Text $Text -AppLogo $LogoPath -UniqueIdentifier $Id | Out-Null } catch {}
}

function Install-Software {
    param(
        [Parameter(Mandatory=$true)][string]$InstallerPath,
        [Parameter(Mandatory=$false)][string]$InstallerArgs,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    $ext = [IO.Path]::GetExtension($InstallerPath).ToLowerInvariant()
    Write-Log "Installer detected: $ext" $LogPath

    switch ($ext) {
        '.msi' {
            $args = "/i `"$InstallerPath`" /qn /norestart"
            Write-Log "Running: msiexec.exe $args" $LogPath
            Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait
        }
        '.exe' {
            $args = $InstallerArgs
            if ([string]::IsNullOrWhiteSpace($args)) {
                # Best-effort default; user can override in the GUI
                $args = '/S'
            }
            Write-Log "Running: $InstallerPath $args" $LogPath
            Start-Process -FilePath $InstallerPath -ArgumentList $args -Wait
        }
        '.msix' {
            Write-Log "Running: Add-AppxPackage -Path $InstallerPath" $LogPath
            Add-AppxPackage -Path $InstallerPath -ErrorAction Stop
        }
        '.appx' {
            Write-Log "Running: Add-AppxPackage -Path $InstallerPath" $LogPath
            Add-AppxPackage -Path $InstallerPath -ErrorAction Stop
        }
        '.msixbundle' {
            Write-Log "Running: Add-AppxPackage -Path $InstallerPath" $LogPath
            Add-AppxPackage -Path $InstallerPath -ErrorAction Stop
        }
        default {
            throw "Unsupported installer type: $ext"
        }
    }
}

function Find-PrimaryExecutable {
    param(
        [Parameter(Mandatory=$true)][DateTime]$InstallStart,
        [Parameter(Mandatory=$true)][DateTime]$InstallEnd,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    # Heuristic for traditional installs: newest changed directory in Program Files
    $candidates = @(
        Join-Path $env:SystemDrive 'Program Files',
        Join-Path $env:SystemDrive 'Program Files (x86)'
    )

    $newest = $null
    $newestTs = $InstallStart.AddMinutes(-2)

    foreach ($base in $candidates) {
        if (-not (Test-Path $base)) { continue }
        try {
            Get-ChildItem -Path $base -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.LastWriteTime -gt $newestTs) {
                    $newest = $_.FullName
                    $newestTs = $_.LastWriteTime
                }
            }
        } catch {}
    }

    if ($newest) {
        Write-Log "Newest install directory heuristic: $newest" $LogPath
        $exe = Get-ChildItem -Path $newest -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1

        if ($exe) {
            return $exe.FullName
        }
    }

    # Heuristic for MSIX/AppX installs: try most recently updated Start Menu link
    $startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    if (Test-Path $startMenu) {
        $lnk = Get-ChildItem $startMenu -Recurse -Filter *.lnk -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $InstallStart.AddMinutes(-2) } |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1
        if ($lnk) {
            Write-Log "Found recent Start Menu shortcut: $($lnk.FullName)" $LogPath
        }
    }

    return $null
}

function Capture-PerfCounters {
    param(
        [Parameter(Mandatory=$true)][int]$Pid,
        [Parameter(Mandatory=$true)][int]$DurationSeconds,
        [Parameter(Mandatory=$true)][string]$OutCsv,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    $interval = 1
    $samples = [Math]::Max([Math]::Floor($DurationSeconds / $interval), 1)

    # Process instance name is not reliably the exe name; resolve via ID process performance counter
    $procInstance = $null
    try {
        $all = Get-Counter "\Process(*)\ID Process" -ErrorAction Stop
        foreach ($s in $all.CounterSamples) {
            if ([int]$s.CookedValue -eq $Pid) {
                $procInstance = $s.InstanceName
                break
            }
        }
    } catch {}

    if (-not $procInstance) {
        Write-Log "Failed to resolve perf counter instance for PID=$Pid" $LogPath
        return
    }

    Write-Log "Perf counter instance: $procInstance" $LogPath

    $counters = @(
        "\Process($procInstance)\% Processor Time",
        "\Process($procInstance)\Working Set - Private",
        "\Process($procInstance)\Handle Count",
        "\Process($procInstance)\Thread Count",
        "\Process($procInstance)\IO Read Bytes/sec",
        "\Process($procInstance)\IO Write Bytes/sec"
    )

    $rows = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $samples; $i++) {
        try {
            $c = Get-Counter -Counter $counters -SampleInterval $interval -MaxSamples 1
            $m = @{}
            foreach ($s in $c.CounterSamples) {
                $name = $s.Path.Split('\\')[-1]
                $m[$name] = [double]$s.CookedValue
            }
            $rows.Add([pscustomobject]@{
                Timestamp = (Get-Date).ToString('o')
                CpuPct = $m['% Processor Time']
                WorkingSetPrivateBytes = $m['Working Set - Private']
                Handles = $m['Handle Count']
                Threads = $m['Thread Count']
                IoReadBytesPerSec = $m['IO Read Bytes/sec']
                IoWriteBytesPerSec = $m['IO Write Bytes/sec']
            })
        } catch {
            Write-Log "Perf capture error: $($_.Exception.Message)" $LogPath
        }
    }

    $rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
}

function Extract-InstallEventLogs {
    param(
        [Parameter(Mandatory=$true)][DateTime]$Start,
        [Parameter(Mandatory=$true)][DateTime]$End,
        [Parameter(Mandatory=$true)][string]$OutFolder,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    New-Item -Path $OutFolder -ItemType Directory -Force | Out-Null

    $queries = @(
        @{ Name = 'Application'; Filter = @{ LogName='Application'; StartTime=$Start; EndTime=$End; ProviderName=@('MsiInstaller') } },
        @{ Name = 'Setup';       Filter = @{ LogName='Setup';       StartTime=$Start; EndTime=$End } },
        @{ Name = 'AppX';        Filter = @{ LogName='Microsoft-Windows-AppXDeploymentServer/Operational'; StartTime=$Start; EndTime=$End } },
        @{ Name = 'AppModel';    Filter = @{ LogName='Microsoft-Windows-AppModel-Runtime/Operational';    StartTime=$Start; EndTime=$End } }
    )

    foreach ($q in $queries) {
        try {
            $events = Get-WinEvent -FilterHashtable $q.Filter -ErrorAction Stop
            $csv = Join-Path $OutFolder ("Events-{0}.csv" -f $q.Name)
            $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, LogName, Message |
                Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

            Write-Log "Exported $($events.Count) events from $($q.Name)" $LogPath
        } catch {
            Write-Log "Event export skipped/failed for $($q.Name): $($_.Exception.Message)" $LogPath
        }
    }
}

function Write-Dashboard {
    param(
        [Parameter(Mandatory=$true)][string]$OutHtml,
        [Parameter(Mandatory=$true)][hashtable]$Summary,
        [Parameter(Mandatory=$true)][string]$PerfCsvName,
        [Parameter(Mandatory=$true)][string]$HistoryJsonName
    )

    $summaryJson = ($Summary | ConvertTo-Json -Depth 5)

    $html = @"
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Soteria Benchmark Dashboard</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0b1020; color: #e9eefc; }
    .card { background: #121a33; border: 1px solid #243055; border-radius: 14px; padding: 16px 18px; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
    .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 14px; }
    .col6 { grid-column: span 6; }
    .col12 { grid-column: span 12; }
    h1 { font-size: 22px; margin: 0 0 6px 0; }
    h2 { font-size: 16px; margin: 0 0 10px 0; opacity: .9; }
    .muted { opacity: .75; }
    .kpi { font-size: 26px; font-weight: 650; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; }
    .pill { padding: 6px 10px; border-radius: 999px; background: #1a2650; border: 1px solid #2a3a6b; }
    button { background: #3b82f6; color: white; border: 0; border-radius: 10px; padding: 10px 12px; font-weight: 600; cursor: pointer; }
    button.secondary { background: #1a2650; border: 1px solid #2a3a6b; }
    a { color: #9ec5ff; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    td { padding: 6px 0; border-bottom: 1px solid #243055; }
    canvas { width: 100%; height: 260px; }
    @media print { body { background: white; color: black; } .card { box-shadow: none; } }
  </style>
  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
</head>
<body>
  <div class=\"row\" style=\"justify-content: space-between; align-items: center; margin-bottom: 14px;\">
    <div>
      <h1>Soteria Benchmark Dashboard</h1>
      <div class=\"muted\" id=\"subtitle\"></div>
    </div>
    <div class=\"row\">
      <button onclick=\"window.print()\">Print / Export to PDF</button>
      <button class=\"secondary\" onclick=\"location.reload()\">Reload</button>
    </div>
  </div>

  <div class=\"grid\">
    <div class=\"card col6\">
      <h2>Summary</h2>
      <div class=\"row\" id=\"pills\"></div>
      <table id=\"summaryTable\"></table>
    </div>

    <div class=\"card col6\">
      <h2>Key KPIs</h2>
      <div class=\"grid\" style=\"grid-template-columns: repeat(2,1fr); gap: 12px;\">
        <div class=\"card\" style=\"background:#0f1630\"><div class=\"muted\">Avg CPU %</div><div class=\"kpi\" id=\"kpiCpu\">-</div></div>
        <div class=\"card\" style=\"background:#0f1630\"><div class=\"muted\">Peak Private WS (MB)</div><div class=\"kpi\" id=\"kpiMem\">-</div></div>
        <div class=\"card\" style=\"background:#0f1630\"><div class=\"muted\">Avg IO Read (KB/s)</div><div class=\"kpi\" id=\"kpiRead\">-</div></div>
        <div class=\"card\" style=\"background:#0f1630\"><div class=\"muted\">Avg IO Write (KB/s)</div><div class=\"kpi\" id=\"kpiWrite\">-</div></div>
      </div>
    </div>

    <div class=\"card col12\">
      <h2>Run performance (time series)</h2>
      <canvas id=\"perfChart\"></canvas>
      <div class=\"muted\" style=\"margin-top:8px\">Source: ${PerfCsvName}</div>
    </div>

    <div class=\"card col12\">
      <h2>Version & performance history (mapped folder)</h2>
      <canvas id=\"histChart\"></canvas>
      <div class=\"muted\" style=\"margin-top:8px\">Source: ${HistoryJsonName}</div>
    </div>
  </div>

  <script>
    const summary = ${summaryJson};
    document.getElementById('subtitle').textContent = `${summary.AppName || 'Unknown App'} — Run ${summary.RunId} (${summary.Timestamp})`;

    // Pills
    const pills = document.getElementById('pills');
    ['AppVersion','InstallerType','TestSeconds','OutputFolder'].forEach(k => {
      const v = summary[k] ?? '-';
      const d = document.createElement('div');
      d.className = 'pill';
      d.textContent = `${k}: ${v}`;
      pills.appendChild(d);
    });

    // Summary table
    const table = document.getElementById('summaryTable');
    const keys = Object.keys(summary).filter(k => !['Perf'].includes(k));
    keys.forEach(k => {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td'); td1.textContent = k; td1.style.opacity = .8;
      const td2 = document.createElement('td'); td2.textContent = (summary[k] ?? '').toString();
      tr.appendChild(td1); tr.appendChild(td2);
      table.appendChild(tr);
    });

    // KPIs
    document.getElementById('kpiCpu').textContent = (summary.AvgCpuPct ?? '-').toFixed ? summary.AvgCpuPct.toFixed(1) : summary.AvgCpuPct;
    document.getElementById('kpiMem').textContent = (summary.PeakWorkingSetPrivateMB ?? '-').toFixed ? summary.PeakWorkingSetPrivateMB.toFixed(1) : summary.PeakWorkingSetPrivateMB;
    document.getElementById('kpiRead').textContent = (summary.AvgIoReadKBps ?? '-').toFixed ? summary.AvgIoReadKBps.toFixed(1) : summary.AvgIoReadKBps;
    document.getElementById('kpiWrite').textContent = (summary.AvgIoWriteKBps ?? '-').toFixed ? summary.AvgIoWriteKBps.toFixed(1) : summary.AvgIoWriteKBps;

    async function loadPerf() {
      const resp = await fetch('${PerfCsvName}');
      const txt = await resp.text();
      const lines = txt.trim().split(/\r?\n/);
      const headers = lines.shift().split(',').map(s=>s.replaceAll('"',''));
      const idx = (name) => headers.indexOf(name);
      const rows = lines.map(l => {
        const cols = l.split(',').map(s=>s.replaceAll('"',''));
        return {
          t: cols[idx('Timestamp')],
          cpu: parseFloat(cols[idx('CpuPct')]),
          mem: parseFloat(cols[idx('WorkingSetPrivateBytes')]) / (1024*1024),
          rd: parseFloat(cols[idx('IoReadBytesPerSec')]) / 1024,
          wr: parseFloat(cols[idx('IoWriteBytesPerSec')]) / 1024,
        };
      });

      new Chart(document.getElementById('perfChart'), {
        type: 'line',
        data: {
          labels: rows.map(r => new Date(r.t).toLocaleTimeString()),
          datasets: [
            { label: 'CPU %', data: rows.map(r => r.cpu) },
            { label: 'Private WS (MB)', data: rows.map(r => r.mem) },
            { label: 'IO Read (KB/s)', data: rows.map(r => r.rd) },
            { label: 'IO Write (KB/s)', data: rows.map(r => r.wr) },
          ]
        },
        options: {
          responsive: true,
          interaction: { mode: 'index', intersect: false },
          plugins: { legend: { labels: { color: '#e9eefc' } } },
          scales: {
            x: { ticks: { color: '#e9eefc' }, grid: { color: 'rgba(233,238,252,.08)' } },
            y: { ticks: { color: '#e9eefc' }, grid: { color: 'rgba(233,238,252,.08)' } }
          }
        }
      });
    }

    async function loadHistory() {
      try {
        const resp = await fetch('${HistoryJsonName}');
        const hist = await resp.json();
        const data = Array.isArray(hist) ? hist : (hist.Runs || []);
        const labels = data.map(r => r.Timestamp);
        new Chart(document.getElementById('histChart'), {
          type: 'line',
          data: {
            labels,
            datasets: [
              { label: 'Avg CPU %', data: data.map(r => r.AvgCpuPct) },
              { label: 'Peak Private WS (MB)', data: data.map(r => r.PeakWorkingSetPrivateMB) }
            ]
          },
          options: {
            responsive: true,
            plugins: { legend: { labels: { color: '#e9eefc' } } },
            scales: {
              x: { ticks: { color: '#e9eefc' }, grid: { color: 'rgba(233,238,252,.08)' } },
              y: { ticks: { color: '#e9eefc' }, grid: { color: 'rgba(233,238,252,.08)' } }
            }
          }
        });
      } catch (e) {
        // History optional
      }
    }

    loadPerf();
    loadHistory();
  </script>
</body>
</html>
"@

    $html | Set-Content -Path $OutHtml -Encoding UTF8
}

# --- Main ---

if (-not (Test-Path $InstallerInfoPath)) {
    Write-Host "InstallerInfo.json not found: $InstallerInfoPath" -ForegroundColor Red
    exit 1
}

Ensure-BurntToast

$info = Get-Content -Path $InstallerInfoPath -Raw | ConvertFrom-Json

$RunFolder = $info.RunFolder
New-Item -Path $RunFolder -ItemType Directory -Force | Out-Null

$LogPath = Join-Path $RunFolder 'logs.txt'
"" | Set-Content -Path $LogPath -Encoding UTF8

Write-Log "Soteria run starting" $LogPath
Write-Log "InstallerPath: $($info.InstallerPath)" $LogPath

Toast -Text @('Soteria', 'Starting install + benchmark...') -LogoPath $Logo -Id 'Soteria001'

$installStart = Get-Date
try {
    Install-Software -InstallerPath $info.InstallerPath -InstallerArgs $info.InstallerArgs -LogPath $LogPath
} catch {
    Write-Log "Install failed: $($_.Exception.Message)" $LogPath
    Toast -Text @('Soteria', 'Install failed - see logs.txt') -LogoPath $Logo -Id 'SoteriaErr'
    exit 2
}
$installEnd = Get-Date

Write-Log "Install completed" $LogPath
Toast -Text @('Soteria', 'Install completed. Starting performance test...') -LogoPath $Logo -Id 'Soteria002'

# Best-effort primary executable discovery
$primaryExe = Find-PrimaryExecutable -InstallStart $installStart -InstallEnd $installEnd -LogPath $LogPath

if (-not $primaryExe) {
    Write-Log "Primary executable could not be determined automatically." $LogPath
    Toast -Text @('Soteria', 'Could not locate app EXE automatically. Collecting logs only...') -LogoPath $Logo -Id 'Soteria003'
} else {
    Write-Log "Primary executable: $primaryExe" $LogPath
}

$testSeconds = [int]($info.TestTimeSeconds)
$runId = $info.RunId

$perfCsv = Join-Path $RunFolder 'perf.csv'
$eventsFolder = Join-Path $RunFolder 'EventLogs'

$appName = ''
$appVersion = ''

$proc = $null
if ($primaryExe -and (Test-Path $primaryExe)) {
    try {
        $fi = Get-Item $primaryExe
        $appName = $fi.VersionInfo.ProductName
        $appVersion = $fi.VersionInfo.ProductVersion
    } catch {}

    $proc = Start-Process -FilePath $primaryExe -PassThru
    Write-Log "Started process PID=$($proc.Id)" $LogPath

    Capture-PerfCounters -Pid $proc.Id -DurationSeconds $testSeconds -OutCsv $perfCsv -LogPath $LogPath

    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    Write-Log "Stopped process" $LogPath
}

# Event logs around installation
Extract-InstallEventLogs -Start $installStart.AddSeconds(-5) -End $installEnd.AddMinutes(2) -OutFolder $eventsFolder -LogPath $LogPath

# Hashes (traditional install heuristic only)
$hashFile = Join-Path $RunFolder 'ApplicationHashes.csv'
try {
    if ($primaryExe) {
        $dir = Split-Path $primaryExe -Parent
        $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.exe','.dll','.sys' }
        $files | ForEach-Object {
            [pscustomobject]@{
                Path   = $_.FullName
                SHA1   = (Get-FileHash -Path $_.FullName -Algorithm SHA1).Hash
                SHA256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
            }
        } | Export-Csv -Path $hashFile -NoTypeInformation -Encoding UTF8
        Write-Log "Hash export complete: $hashFile" $LogPath
    }
} catch {
    Write-Log "Hash export failed: $($_.Exception.Message)" $LogPath
}

# VirusTotal (optional)
$vtOut = Join-Path $RunFolder 'VirusTotalCheck.json'
if (-not [string]::IsNullOrWhiteSpace($VirusTotalAPIKey)) {
    try {
        $sha1 = (Get-FileHash -Path $info.InstallerPath -Algorithm SHA1).Hash
        $headers = @{ 'accept'='application/json'; 'x-apikey'=$VirusTotalAPIKey }
        $url = "https://www.virustotal.com/api/v3/files/$sha1"
        $resp = Invoke-WebRequest -Uri $url -Method GET -Headers $headers
        $resp.Content | Set-Content -Path $vtOut -Encoding UTF8
        Write-Log "VirusTotal lookup saved: $vtOut" $LogPath
    } catch {
        Write-Log "VirusTotal lookup failed: $($_.Exception.Message)" $LogPath
    }
} else {
    Write-Log "VirusTotal skipped (no API key)." $LogPath
}

# Summarise perf
$avgCpu = $null; $peakWsMb = $null; $avgRead = $null; $avgWrite = $null
if (Test-Path $perfCsv) {
    try {
        $p = Import-Csv $perfCsv
        if ($p.Count -gt 0) {
            $avgCpu = ($p | Measure-Object -Property CpuPct -Average).Average
            $peakWsMb = (($p | Measure-Object -Property WorkingSetPrivateBytes -Maximum).Maximum) / (1024*1024)
            $avgRead = (($p | Measure-Object -Property IoReadBytesPerSec -Average).Average) / 1024
            $avgWrite = (($p | Measure-Object -Property IoWriteBytesPerSec -Average).Average) / 1024
        }
    } catch {}
}

$installerType = ([IO.Path]::GetExtension($info.InstallerPath)).TrimStart('.').ToUpperInvariant()

$summary = @{
    Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    RunId = $runId
    OutputFolder = $RunFolder
    InstallerType = $installerType
    InstallerUrl = $info.InstallerUrl
    InstallerArgs = $info.InstallerArgs
    TestSeconds = $testSeconds
    AppName = $appName
    AppVersion = $appVersion
    InstallStart = $installStart.ToString('o')
    InstallEnd = $installEnd.ToString('o')
    AvgCpuPct = $avgCpu
    PeakWorkingSetPrivateMB = $peakWsMb
    AvgIoReadKBps = $avgRead
    AvgIoWriteKBps = $avgWrite
}

$summaryJsonPath = Join-Path $RunFolder 'summary.json'
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryJsonPath -Encoding UTF8

# Persistent history file (mapped folder)
$historyPath = Join-Path (Join-Path $Root 'History') 'history.json'
try {
    $existing = @()
    if (Test-Path $historyPath) {
        $raw = Get-Content $historyPath -Raw
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $existing = $raw | ConvertFrom-Json
        }
    }
    if (-not ($existing -is [System.Collections.IEnumerable])) { $existing = @() }
    $combined = @($existing) + @($summary)
    $combined | ConvertTo-Json -Depth 6 | Set-Content -Path $historyPath -Encoding UTF8
} catch {
    Write-Log "History update failed: $($_.Exception.Message)" $LogPath
}

# Dashboard
$dashboardPath = Join-Path $RunFolder 'dashboard.html'
Write-Dashboard -OutHtml $dashboardPath -Summary $summary -PerfCsvName 'perf.csv' -HistoryJsonName (Join-Path (Join-Path '..' '..') 'History\history.json')

Toast -Text @('Soteria', 'Benchmark complete. Dashboard generated in results folder.') -LogoPath $Logo -Id 'Soteria004'

# Open dashboard automatically (best effort)
try { Start-Process $dashboardPath } catch {}

Write-Log "Run complete. Dashboard: $dashboardPath" $LogPath

# Shutdown Sandbox
Start-Sleep -Seconds 5
cmd.exe /c "shutdown -s -t 0" | Out-Null
