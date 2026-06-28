# Testing notes

Use benign test installers first, such as an internally owned hello-world MSI or EXE.

Recommended first tests:

1. Build the sandbox agent.
2. Copy `sandbox-agent.exe` next to the host app executable.
3. Start the Tauri dev app.
4. Configure a VirusTotal API key in Settings.
5. Select a benign EXE.
6. Calculate hashes.
7. Optionally perform a VirusTotal lookup.
8. Run with networking disabled for the first test.
9. After the sandbox closes or the agent finishes, inspect the run folder under `%APPDATA%`/local application data for `summary.json`.

The current MVP writes raw telemetry to the run output folder. Full UI import and report browsing are intentionally left as the next small iteration.
