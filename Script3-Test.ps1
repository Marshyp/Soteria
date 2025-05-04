# Variables
$InstallerInfoPath = "C:\SandboxTest\InstallerInfo.json"
$VirusTotalAPIKey = "{YOURKEYHERE}"
$VirusTotalResultPath = "C:\SandboxTest\VirusTotalCheck.txt"
$HashOutputPath = "C:\SandboxTest\ApplicationHashes.txt"
$MonitoringLogs = "C:\SandboxTest\Monitoring.txt"
$Logo = "C:\SandboxTest\Personalisation\icon.jpg"
$logFilePath = "C:\SandboxTest\logs.txt"
$TestTime = "120" # The number of seconds that application should be tested for. Default: 2 Minutes (120 Seconds)

# Confirm log file exists
if (!(Test-Path $logFilePath))
{
   New-Item -path $logFilePath -type "file" -value "Test script started"
   Write-Host "Created new file and beginning test"
} else {
  Clear-Content -Path $logFilePath
  Add-Content -path $logFilePath -value "Test script started"
  Write-Host "File already exists"
}

# Helper function for logging
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append
}

# Start logging
Log-Message "Script execution underway, logging started..."

# Post a Toast Notification to advise that testing is starting
Log-Message "Attempting to send toast notification."
try {
    New-BurntToastNotification -Text "Script started", "The testing script has started. Please allow time for the testing to complete..." -AppLogo $Logo -UniqueIdentifier 'AppTest002'
    Log-Message "Toast notification sent successfully."
} catch {
    Log-Message "Error sending toast notification: $($_.Exception.Message)"
}

### START MAIN TESTING SCRIPT ###

# Load Installer Info
if (-not (Test-Path $InstallerInfoPath)) {
    Log-Message "Install info file not found: $InstallerInfoPath"
    exit
}

Log-Message "Installer info file found - continuing..."
$InstallerInfo = Get-Content -Path $InstallerInfoPath | ConvertFrom-Json


# Determine newest installed application directory
$InstalledPaths = @(
    "C:\Program Files",
    "C:\Program Files (x86)"
)

$NewestInstalledDir = $null
$NewestInstallTime = Get-Date -Date "04/12/2024"

foreach ($Path in $InstalledPaths) {
    $Dirs = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue
    foreach ($Dir in $Dirs) {
        if ($Dir.LastWriteTime -gt $NewestInstallTime) {
            $NewestInstalledDir = $Dir.FullName
            $NewestInstallTime = $Dir.LastWriteTime
        }
    }
}

if (-not $NewestInstalledDir) {
    Log-Message "Installed application directory not located. Exiting..."
    exit
}

Log-Message "Newest installed application directory: $NewestInstalledDir"

# Locate primary executable in the directory
Log-Message "Attempting to locate the primary executable" 
$PrimaryExecutable = Get-ChildItem -Path $NewestInstalledDir -Recurse -Include *.exe -ErrorAction SilentlyContinue |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1

if (-not $PrimaryExecutable) {
    
    Log-Message "No executable files found in the application directory."
    exit
}

Log-Message "Primary application executable located: $($PrimaryExecutable.FullName)"

# Post a Toast Notification to advise that application testing is starting
Log-Message "Attempting to send toast notification for Test Started."
try {
    New-BurntToastNotification -Text "Test Started", "Application testing has started. Please allow time for the testing to complete..." -AppLogo $Logo -UniqueIdentifier 'AppTest002'
    Log-Message "Toast notification sent successfully."
} catch {
    Log-Message "Error sending toast notification: $($_.Exception.Message)"
}

# Open Task Manager
Log-Message "Opening Task Manager"
Start-Process -FilePath "taskmgr.exe"
Start-Sleep -Seconds 2 # Give Task Manager a moment to open

# Start application for testing
Log-Message "Starting application for testing..."
$Process = Start-Process -FilePath $PrimaryExecutable.FullName -PassThru
Log-Message "Allowing $Time seconds for testing"
Start-Sleep -Seconds $TestTime # Allow application to run for 2 minutes

# Monitor Process (CPU, Memory, Threads)
Log-Message "Monitoring application performance..."
$MonitoringData = @{
    "StartTime" = $Process.StartTime
    "CPUUsage"  = $Process.CPU
    "Memory"    = $Process.WorkingSet64
    "Threads"   = $Process.Threads.Count
    "EndTime"   = (Get-Date)
}
$MonitoringData | Out-File -FilePath $MonitoringLogs -Append

# Post a Toast Notification to advise that testing is completed
Log-Message "Attempting to send test completed notification."
try {
    New-BurntToastNotification -Text "Test Completed", "Testing has now completed, please wait whilst we collect the results of the software test and close applications." -AppLogo $Logo -UniqueIdentifier 'AppTest003'
    Log-Message "Toast notification sent successfully."
} catch {
    Log-Message "Error sending toast notification: $($_.Exception.Message)"
}

# Stop application
Log-Message "Stopping application after testing."
Stop-Process -Id $Process.Id -Force

# Close Task Manager
Log-Message "Closing Task Manager"
Stop-Process -Name "taskmgr" -Force

# Collect Hashes
# Post a Toast Notification to advise that hash collection is starting

Log-Message "Attempting to start hash collection."
try {
    New-BurntToastNotification -Text "File Hash Collection", "Please wait whilst we collect the file hashes for WDAC policy creation..." -AppLogo $Logo -UniqueIdentifier 'AppTest004'
    Log-Message "Toast notification sent successfully."
} catch {
    Log-Message "Error sending toast notification: $($_.Exception.Message)"
}

# Scan the folder and subfolders to generate a comma-separated list of SHA1 hashes
Log-Message "Hash scanning started"
$hashes = Get-ChildItem -Path $NewestInstalledDir -Recurse -File |
Where-Object { $_.Extension -in ".exe", ".dll", ".sys" } |
ForEach-Object {
    (Get-FileHash -Path $_.FullName -Algorithm SHA1).Hash
    (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
}

# Combine the hashes into a comma-separated string
Log-Message "Creating CSV string for hashes"
$hashesString = $hashes -join ','

# Write the hashes to the output file
Set-Content -Path $HashOutputPath -Value $hashesString
Log-Message "SHA1 hashes from '$folderPath' and all subfolders have been successfully exported as a comma-separated list."

# VirusTotal File Upload - SHA1 Hash Upload
# Post a Toast Notification to advise that VT Test is underway

Log-Message "Attempting VirusTotal Upload."
try {
    New-BurntToastNotification -Text "VirusTotal", "Please wait whilst we check the install package against VirusTotal. You will see the outcome of this test in the Software Test folder." -AppLogo $Logo -UniqueIdentifier 'AppTest005'
    Log-Message "Toast notification sent successfully."
} catch {
    Log-Message "Error sending toast notification: $($_.Exception.Message)"
}

# Load Installer Info
Log-Message "Loadinging Installer Info for upload"
if (-not (Test-Path $InstallerInfoPath)) {
    Log-Message "Installer info file not found: $InstallerInfoPath" -ForegroundColor Red
    exit
}

$InstallerInfo = Get-Content -Path $InstallerInfoPath | ConvertFrom-Json

# Ensure the installer file exists
if (-not (Test-Path $InstallerInfo.InstallerPath)) {
    Log-Message "Installer file not found. Skipping VirusTotal scan."
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
            Log-Message "Error: $($response.StatusCode) - $($response.StatusDescription)"
            "ERROR: An error occurred while fetching the VirusTotal result. Response: $($response.StatusCode) - $($response.StatusDescription)" | Out-File -FilePath $VirusTotalResultPath
        }

    } catch {
        # If an error occurs, write error details to VirusTotal result path
        "ERROR: An error occurred while fetching the VirusTotal result. Error details: $($_.Exception.Message)" | Out-File -FilePath $VirusTotalResultPath
    }
}

Log-Message "VirusTotal scan results saved to: $VirusTotalResultPath"

# Post a Toast Notification to advise that the script is complete
Log-Message "Script Complete."
try {
    New-BurntToastNotification -Text "Testing Completed",  " All software testing and log collection has now completed. We will continue to close down the sandbox environment." -AppLogo $Logo -UniqueIdentifier 'AppTest006'
    start-sleep 5
    Log-Message "Toast notification sent successfully."
} catch {
    Log-Message "Error sending toast notification: $($_.Exception.Message)"
}

# Shut down Windows Sandbox after testing
Log-Message "Shutting down Windows Sandbox..."
Stop-computer -computername localhost -Force
cmd.exe /c "shutdown -s -t 0"

Log-Message "Script 3 has finished execution and Windows Sandbox has been shut down."