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
    (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
}

# Combine the hashes into a comma-separated string
$hashesString = $hashes -join ','

# Write the hashes to the output file
Set-Content -Path $HashOutputPath -Value $hashesString
Write-Host "SHA1 hashes from '$folderPath' and all subfolders have been successfully exported as a comma-separated list." -ForegroundColor Green

# VirusTotal File Upload - SHA1 Hash Upload
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
    "ERROR: Installer file not found." | Out-File -FilePath $VirusTotalResultPath
} else {
    try {
        # Get the SHA1 hash of the installer file
        $FilePath = $InstallerInfo.InstallerPath
        $sha1Hash = (Get-FileHash -Path $FilePath -Algorithm SHA1).Hash

        # Prepare the headers for the request
        $headers = @{
            "accept" = "application/json"
            "x-apikey" = $VirusTotalAPIKey
        }

        # Send the GET request to VirusTotal to check the file by SHA1 hash
        $url = "https://www.virustotal.com/api/v3/files/$sha1Hash"
        $response = Invoke-WebRequest -Uri $url -Method GET -Headers $headers

       # Check for successful response
        if ($response.StatusCode -eq 200) {
            # Get the full response content as text (to avoid truncation)
            $responseContent = $response.Content | Out-String

            # Convert the response content to JSON and save it to the result path
            $responseContent | Out-File -FilePath $VirusTotalResultPath
        } else {
            Write-Host "Error: $($response.StatusCode) - $($response.StatusDescription)" -ForegroundColor Red
            "ERROR: An error occurred while fetching the VirusTotal result. Response: $($response.StatusCode) - $($response.StatusDescription)" | Out-File -FilePath $VirusTotalResultPath
        }

    } catch {
        # If an error occurs, write error details to VirusTotal result path
        "ERROR: An error occurred while fetching the VirusTotal result. Error details: $($_.Exception.Message)" | Out-File -FilePath $VirusTotalResultPath
    }
}

Write-Host "VirusTotal scan results saved to: $VirusTotalResultPath"

# Shut down Windows Sandbox after testing
Write-Host "Shutting down Windows Sandbox..."
Stop-computer -computername localhost -Force
cmd.exe /c "shutdown -s -t 0"

Write-Host "Script 3 has finished execution and Windows Sandbox has been shut down."
