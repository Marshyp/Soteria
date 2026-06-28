param(
  [Parameter(Mandatory=$true)][string]$SummaryPath
)

if (!(Test-Path $SummaryPath)) {
  throw "summary.json not found: $SummaryPath"
}

$summary = Get-Content $SummaryPath -Raw | ConvertFrom-Json
$summary | ConvertTo-Json -Depth 20
Write-Host "This helper validates and prints the summary. The Tauri UI database ingest button is the next intended iteration."
