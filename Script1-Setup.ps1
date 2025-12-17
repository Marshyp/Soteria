<#
Soteria - Host bootstrap

Run this on the HOST (not inside Windows Sandbox).
It creates/updates the mapped folder, writes a .wsb file, and launches Windows Sandbox.

The in-sandbox entrypoint is Script2-Menu.ps1 which presents a GUI to collect:
 - download URL
 - installer arguments (optional)
 - test duration
 - results subfolder name
#>

Clear-Host

$Root = Join-Path $env:SystemDrive 'SandboxTest'
$SandboxConfigPath = Join-Path $Root 'TestSandbox.wsb'

if (-not (Test-Path $Root)) {
    New-Item -Path $Root -ItemType Directory -Force | Out-Null
}

# Ensure results/history folders exist on host (persist across runs)
$ResultsRoot = Join-Path $Root 'Results'
$HistoryRoot = Join-Path $Root 'History'
New-Item -Path $ResultsRoot -ItemType Directory -Force | Out-Null
New-Item -Path $HistoryRoot -ItemType Directory -Force | Out-Null

Write-Host "Soteria host folder ready at: $Root"

# Write Sandbox configuration
$SandboxConfig = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$Root</HostFolder>
      <SandboxFolder>$Root</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File $Root\Script2-Menu.ps1</Command>
  </LogonCommand>
</Configuration>
"@

$SandboxConfig | Set-Content -Path $SandboxConfigPath -Encoding UTF8
Write-Host "Sandbox configuration written: $SandboxConfigPath"

Write-Host "Launching Windows Sandbox..."
Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe') -ArgumentList $SandboxConfigPath

Write-Host "Windows Sandbox launched. Close the Sandbox when the dashboard is generated to finish the run."