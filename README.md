# Soteria
Soteria is an automated tool for testing software and creating WDAC policies around the software. This project is currently a WIP

### NOTICE
This relies on a mapped folder on the host at `%SystemDrive%\SandboxTest`.

### Quick start
1. Copy the project files into `%SystemDrive%\SandboxTest` on the host.
2. Run `Script1-Setup.ps1` on the host.
3. In the Sandbox GUI, paste a download URL for an installer (`.exe`, `.msi`, `.msix`/`.msixbundle`), choose a results subfolder name, and run the test.
4. Results and a dashboard are written under `%SystemDrive%\SandboxTest\Results\<Subfolder>\Run-<timestamp>`.

---

## TO DO:
- [X] Credits file creation
- [X] Rectify issues with VirusTotal API check
- [X] Code cleanup
- [X] Allow for a variable of time to test
- [X] Logging method to output errors / progress to a log file (clears on each run)
- [X] Toast notifications to showcase progress of script
- [X] Removal of write-host (we're running silently!)
- [X] Custom background to make it clear that we're running application sandboxing
- [ ] Extract event logs relating to application
- [X] Integration with performance counters (Resource Monitor-equivalent metrics) to output performance metrics
- [X] Extract event logs relating to application install (MSI/AppX/Setup window)
- [ ] Automated creation of WDAC policies
- [ ] Automation to push policy into Intune
- [X] Allow for splitting the results of tests into subfolders for ease of searching / multiple loads
- [ ] Build out Devops and Github workflows
- [ ] Integrate a screen recorder to record output for further analysis
