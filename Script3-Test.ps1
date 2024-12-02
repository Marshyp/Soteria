# Variables
$InstallerInfoPath = "C:\SandboxTest\$SoftwareName\InstallerInfo.json"  # Update with software-specific folder
$VirusTotalAPIKey = "{YOUR API KEY HERE}"
$VirusTotalResultPath = "C:\SandboxTest\$SoftwareName\VirusTotalCheck.txt"
$HashOutputPath = "C:\SandboxTest\$SoftwareName\ApplicationHashes.txt"
$MonitoringLogs = "C:\SandboxTest\$SoftwareName\Monitoring.txt"
$filePath = "C:\SandboxTest\$SoftwareName\file.txt"
$fileContent = "Application Testing Underway!"

# Load Installer Info
if (-not (Test-Path $InstallerInfoPath)) {
    Write-Host "Installer info file not found: $InstallerInfoPath" -ForegroundColor Red
    exit
}

$InstallerInfo = Get-Content -Path $InstallerInfoPath | ConvertFrom-Json

# Determine newest installed application directory
$InstalledPaths = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "$env:APPDATA"
)

$NewestInstalledDir = $null
$NewestInstallTime = Get-Date -Date "01/01/1970"

foreach ($Path in $InstalledPaths) {
    $Dirs = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
    foreach ($Dir in $Dirs) {
        if ($Dir.LastWriteTime -gt $NewestInstallTime) {
            $NewestInstalledDir = $Dir.FullName
            $NewestInstallTime = $Dir.LastWriteTime
        }
    }
}

if (-not $NewestInstalledDir) {
    Write-Host "No installed application directories found." -ForegroundColor Red
    exit
}

Write-Host "Newest installed application directory: $NewestInstalledDir"

# Locate primary executable in the directory
$PrimaryExecutable = Get-ChildItem -Path $NewestInstalledDir -Recurse -Include *.exe -ErrorAction SilentlyContinue |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1

if (-not $PrimaryExecutable) {
    Write-Host "No executable files found in the application directory." -ForegroundColor Red
    exit
}

Write-Host "Primary application executable: $($PrimaryExecutable.FullName)"

# Open Notepad with a message for the user (before launching Task Manager and application)
Set-Content -Path $filePath -Value $fileContent
Start-Process "notepad.exe" -ArgumentList $filePath
Start-Sleep -Seconds 1 # Ensure notepad has time to open

# Open Task Manager
Start-Process -FilePath "taskmgr.exe"
Start-Sleep -Seconds 2 # Give Task Manager a moment to open

# Start application for testing
Write-Host "Starting application for testing..."
$Process = Start-Process -FilePath $PrimaryExecutable.FullName -PassThru
Start-Sleep -Seconds 10 # Allow application to run for 2 minutes

# Monitor Process (CPU, Memory, Threads)
Write-Host "Monitoring application performance..."
$MonitoringData = @{
    "StartTime" = $Process.StartTime
    "CPUUsage"  = $Process.CPU
    "Memory"    = $Process.WorkingSet64
    "Threads"   = $Process.Threads.Count
    "EndTime"   = (Get-Date)
}
$MonitoringData | Out-File -FilePath $MonitoringLogs -Append

# Stop application
Write-Host "Stopping application after testing."
Stop-Process -Id $Process.Id -Force

# Close Notepad
Stop-Process -Name "notepad" -Force

# Close Task Manager
Stop-Process -Name "taskmgr" -Force

# Collect Hashes
# Scan the folder and subfolders to generate a comma-separated list of SHA1 hashes
$hashes = Get-ChildItem -Path $NewestInstalledDir -Recurse -File |
Where-Object { $_.Extension -in ".exe", ".dll", ".sys" } |
ForEach-Object {
    (Get-FileHash -Path $_.FullName -Algorithm SHA1).Hash
    (Get-FileHash -Path $_.FullName -Algorithm
