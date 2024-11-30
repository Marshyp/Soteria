# Variables
$InstallerInfoPath = "C:\SandboxTest\InstallerInfo.json"
$VirusTotalAPIKey = "{YOUR API KEY HERE}"
$VirusTotalResultPath = "C:\SandboxTest\VirusTotalCheck.txt"
$HashOutputPath = "C:\SandboxTest\ApplicationHashes.txt"
$MonitoringLogs = "C:\SandboxTest\Monitoring.txt"
$filePath = "C:\SandboxTest\file.txt"
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
# Load Installer Info
if (-not (Test-Path $InstallerInfoPath)) {
    Write-Host "Installer info file not found: $InstallerInfoPath" -ForegroundColor Red
    exit
}

$InstallerInfo = Get-Content -Path $InstallerInfoPath | ConvertFrom-Json

# Ensure the installer file exists
if (-not (Test-Path $InstallerInfo.InstallerPath)) {
    Write-Host "Installer file not found. Skipping VirusTotal scan." -ForegroundColor Yellow
    # Write error to VirusTotal result path
    "ERROR: An error occurred whilst attempting to upload file to Virus Total" | Out-File -FilePath $VirusTotalResultPath
} else {
    try {
        # Prepare the headers for the request
        $headers = @{
            "accept" = "application/json"
            "x-apikey" = $VirusTotalAPIKey
            "content-type" = "multipart/form-data; boundary=---011000010111000001101001"
        }

        # Prepare the body for the file upload, which includes the multipart boundary
        $Boundary = "---011000010111000001101001"
        $FilePath = $InstallerInfo.InstallerPath
        $FileContent = [System.IO.File]::ReadAllBytes($FilePath)

        # Create the multipart form-data body
        $Body = @"
$Boundary
Content-Disposition: form-data; name="file"; filename="$(Split-Path -Leaf $FilePath)"
Content-Type: application/octet-stream

$( [System.Text.Encoding]::ASCII.GetString($FileContent) )

$Boundary--
"@

        # Send the POST request to VirusTotal
        $response = Invoke-WebRequest -Uri 'https://www.virustotal.com/api/v3/files' -Method POST -Headers $headers -Body $Body

        # Check for successful response and write to the result file
        if ($response.StatusCode -eq 200) {
            $response.Content | ConvertFrom-Json | Out-File -FilePath $VirusTotalResultPath
        } else {
            Write-Host "Error: $($response.StatusCode) - $($response.StatusDescription)" -ForegroundColor Red
            "ERROR: An error occurred whilst attempting to upload file to Virus Total. Response: $($response.StatusCode) - $($response.StatusDescription)" | Out-File -FilePath $VirusTotalResultPath
        }

    } catch {
        # If an error occurs, write error details to VirusTotal result path
        "ERROR: An error occurred whilst attempting to upload file to Virus Total. Error details: $($_.Exception.Message)" | Out-File -FilePath $VirusTotalResultPath
    }
}

Write-Host "VirusTotal scan results saved to: $VirusTotalResultPath"

# Shut down Windows Sandbox after testing
Write-Host "Shutting down Windows Sandbox..."
Stop-computer -computername localhost -Force
cmd.exe /c "shutdown -s -t 0"

Write-Host "Script 3 has finished execution and Windows Sandbox has been shut down."
