# Sandbox Analyzer

Soteria launches a user-selected installer or executable inside Windows Sandbox, collects behavioural telemetry, checks the SHA-256 hash against VirusTotal, and stores analysis history in SQLite.

**NOTE** - This rebuild is a WIP, and not intended for public use at this moment in time. 

- Rust/Tauri host app
- React-based modern UI
- SQLite schema and host database commands
- VirusTotal hash lookup command
- Windows Sandbox `.wsb` generation
- Mapped input, agent, and output folders
- Rust sandbox agent
- Before/after filesystem snapshots
- Before/after registry snapshots
- Basic process metric polling
- Network connection snapshot
- Firewall rule snapshots
- Settings for theme, database reset, VirusTotal key, default sandbox duration, and networking

## Requirements

- Windows 10/11 Pro, Enterprise, or Education with Windows Sandbox support
- Virtualisation enabled in BIOS/UEFI
- Rust toolchain
- Node.js LTS
- Tauri prerequisites for Windows
- Optional: VirusTotal API key

Enable Windows Sandbox from elevated PowerShell:

```powershell
./scripts/enable-windows-sandbox.ps1
```

Restart if Windows asks you to.

## Build the sandbox agent

```powershell
cargo build -p sandbox-agent --release
```

Copy the agent next to the host executable when doing real sandbox launches:

```powershell
Copy-Item .\target\release\sandbox-agent.exe .\src-tauri\target\debug\sandbox-agent.exe -Force
```

For development, you can also copy it manually into the generated run folder's `agent` directory before opening the `.wsb` file.

## Run the host app in development

Install UI dependencies:

```powershell
cd ui
npm install
cd ..
```

Run the Tauri app:

```powershell
cargo tauri dev
```

## First test flow

1. Open the app.
2. Go to Settings and add a VirusTotal API key if you have one.
3. Select a benign installer or EXE by entering its full path.
4. Click **Calculate hash**.
5. Optionally click **VirusTotal lookup**.
6. Choose the analysis duration.
7. Keep networking disabled for the first run.
8. Click **Run analysis**.
9. Windows Sandbox should open and run the bootstrap script.
10. The sandbox agent writes `summary.json`, `agent.log`, and registry snapshots into the mapped output folder.

## Current limitations

- The UI currently launches runs and lists stored runs, but automatic import of `summary.json` into SQLite needs a small UI action added in the next iteration.
- File and registry monitoring is before/after snapshot based, not full event streaming.
- Network collection uses a point-in-time `Get-NetTCPConnection` snapshot.
- Authenticode signature verification is not yet implemented.
- No file upload to VirusTotal is implemented. This is intentional; uploading should remain explicit and opt-in.
- The sandbox agent attempts to start the sample but does not yet handle complex MSI installation flows, UAC-like prompts, or reboot-required installers.

## Task List

1. Add an **Import Results** button that reads `summary.json` from the output folder and calls `ingest_run`.
2. Add a detailed results screen for file, registry, network, firewall, process metrics, and raw JSON.
3. Add baseline selection and comparison from the Runs screen.
4. Replace snapshot-only telemetry with ETW collection for process, file, registry, and network events.
5. Add Authenticode signature metadata.
6. Add safer sandbox profiles and warnings for networking-enabled analyses.
