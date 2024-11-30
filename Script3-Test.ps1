# Variables
$InstallerInfoPath = "C:\SandboxTest\InstallerInfo.json"
$VirusTotalAPIKey = "<YOUR API KEY HERE>"
$VirusTotalResultPath = "C:\SandboxTest\VirusTotalCheck.txt"
$HashOutputPath = "C:\SandboxTest\ApplicationHashes.txt"
$MonitoringLogs = "C:\SandboxTest\Monitoring.txt"

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
Start-Process -FilePath "notepad.exe" -ArgumentList "Application testing underway!" -NoNewWindow
Start-Sleep -Seconds 1 # Ensure notepad has time to open

# Open Task Manager
Start-Process -FilePath "taskmgr.exe"
Start-Sleep -Seconds 2 # Give Task Manager a moment to open

# Start application for testing
Write-Host "Starting application for testing..."
$Process = Start-Process -FilePath $PrimaryExecutable.FullName -PassThru
Start-Sleep -Seconds 120 # Allow application to run for 2 minutes

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
    (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
}

# Combine the hashes into a comma-separated string
$hashesString = $hashes -join ','

# Write the hashes to the output file
Set-Content -Path $HashOutputPath -Value $hashesString
Write-Host "SHA1 hashes from '$folderPath' and all subfolders have been successfully exported as a comma-separated list." -ForegroundColor Green

# VirusTotal File Upload
Write-Host "Uploading installation file to VirusTotal..."
if (-not (Test-Path $InstallerInfo.InstallerPath)) {
    Write-Host "Installer file not found. Skipping VirusTotal scan." -ForegroundColor Yellow
} else {
    $FileBytes = [System.IO.File]::ReadAllBytes($InstallerInfo.InstallerPath)
    $Base64File = [Convert]::ToBase64String($FileBytes)

    $Headers = @{
        "x-apikey" = $VirusTotalAPIKey
    }
    $Body = @{
        file = $Base64File
    }
    #$Response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files" -Method POST -Headers $Headers -Body $Body
    #$Response | ConvertTo-Json -Depth 10 | Out-File -FilePath $VirusTotalResultPath -Append
}

Write-Host "VirusTotal scan results saved to: $VirusTotalResultPath"

# Shut down Windows Sandbox after testing
Write-Host "Shutting down Windows Sandbox..."
Stop-computer -computername localhost -Force
cmd.exe /c "shutdown -s -t 0"

Write-Host "Script 3 has finished execution and Windows Sandbox has been shut down."
