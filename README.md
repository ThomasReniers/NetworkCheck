# NetworkCheck

**Read-only Windows network diagnostics and security configuration checks, with clear CLI reports rendered in Docker.** Inspect connectivity, identify local listening ports and their associated services or applications, review possible security issues, and get non-destructive troubleshooting suggestions.

> **Windows-only scanner.** The host PowerShell script reads Windows network and service information; the Linux Docker container formats the report. Building the Docker image alone does **not** install the Windows `networkcheck` command. **NetworkCheck is not a comprehensive CVE, malware, exploit, internet-perimeter, or subnet scanner.**

## Installation — choose a method

### Method 1: Clone the repository and build locally

Requirements: Windows 10/11, Windows PowerShell 5.1 or PowerShell 7+, Docker Desktop running Linux containers, and Git.

```powershell
git clone https://github.com/ThomasReniers/NetworkCheck.git
cd NetworkCheck
docker build --no-cache -t networkcheck:latest .
```

To use it from anywhere, add the cloned **NetworkCheck** folder to your Windows user `PATH` (it contains `networkcheck.bat`), then reopen your terminal. Alternatively, copy `networkcheck.bat` into an existing `Batchfiles` folder that is already on your `PATH`, **provided that** `Batchfiles` and `NetworkCheck` are sibling folders. The launcher supports both layouts.

### Method 2: Build the Docker image directly from GitHub

No clone is required **for the Docker image**:

```powershell
docker build --no-cache -t networkcheck:latest https://github.com/ThomasReniers/NetworkCheck.git
```

**The CLI still needs two local Windows files.** Download [networkcheck.ps1](https://raw.githubusercontent.com/ThomasReniers/NetworkCheck/main/networkcheck.ps1) and [networkcheck.bat](https://raw.githubusercontent.com/ThomasReniers/NetworkCheck/main/networkcheck.bat) to a local folder named `NetworkCheck`. The script creates `NetworkCheck\reports` automatically. Add that folder to your Windows user `PATH` and reopen the terminal. Alternatively, put the batch launcher in a sibling `Batchfiles` directory already on your `PATH`.

> Download the **raw** files, not the GitHub HTML preview pages. The launcher, host script and Docker image must come from compatible versions.

**PowerShell security:** The launcher does not override execution policies. If a downloaded script is blocked, review its source and follow your organization's file trust and PowerShell policy procedures. Do not disable security controls to run NetworkCheck.

## Run a network check

```powershell
networkcheck                          # Local network check + example.com:443
networkcheck -o txt                   # Terminal + plain text report
networkcheck -o md                    # Terminal + Markdown report
networkcheck -o json                  # Terminal + structured JSON report
networkcheck -t example.com           # Select a target hostname/IP address
networkcheck -t 192.168.1.1 --port 443 # Test a device you are authorized to access
networkcheck --help
```

Only `txt`, `md` and `json` are supported after `-o`. Reports are saved with automatic timestamps in the local `NetworkCheck/reports/` directory. Without `-o`, no permanent report is saved. Temporary Docker-renderer input is removed after each scan, including its staging directory when empty.

After the first scan, a managed container named **`networkcheck`** remains visible in Docker Desktop. It is **Stopped** between scans, starts only to render a report, and stops afterward. The container is created from **`networkcheck:latest`** and refreshed when the tagged image changes. No `docker compose` or `docker down` is required.

## What does it examine?

NetworkCheck reads local Windows network adapters, IP addresses, DNS servers and routes; checks a gateway response where available; resolves one selected target; and attempts one TCP connection. It also inspects local listening TCP sockets, related processes and Windows services, application metadata, Windows Firewall profiles, SMBv1, SMB signing, RDP, Remote Registry and LLMNR policy.

A service is matched to a listening process by PID. Multiple services hosted by one process are shown as possible associations rather than falsely claiming one owns the socket. Device names are reported only when supported by direct evidence; a remote printer's configured port is not the same as a local listening port. No external port sweep, printer discovery, credential attempt or exploitation is performed.

Reports contain the following sections:

```text
SUMMARY
SOURCE
1. NETWORK ADAPTERS
2. CONNECTIVITY
3. LISTENING PORTS
4. SECURITY & VULNERABILITY CHECKS
5. CONCLUSION
6. ISSUES
7. TROUBLESHOOTING
COLLECTION COVERAGE
DISCLAIMER
```

**SUMMARY / Connectivity** describes the outcome of the selected network tests (`OK`, `ISSUES DETECTED`, `INCONCLUSIVE`). **SUMMARY / Security** independently describes configuration risk (`NO CLEAR HIGH-RISK FINDINGS`, `REVIEW REQUIRED`, `INCOMPLETE`). An operating internet connection does not prove the computer is secure; a local listening port does not prove that it is reachable from outside your network.

`ISSUES` lists findings supported by observed information with severity, confidence and evidence. `TROUBLESHOOTING` suggests safe, non-destructive actions. `COLLECTION COVERAGE` identifies failed or unavailable checks; missing data is not silently interpreted as a disabled service or healthy setting. JSON reports contain structured diagnostic information (schema version 3).

**Terminal colors:** Status labels may be colored for readability. Saved TXT, Markdown and JSON reports contain no ANSI color codes.

## Project files

```text
NetworkCheck/
├── Dockerfile
├── networkcheck.ps1
├── networkcheck.bat
├── .dockerignore
├── .gitignore
├── LICENSE
├── README.md
└── reports/
    └── .gitkeep
```

A local `.git/` directory is normal after `git clone` or `git init`. Git uses it to track changes and commits; it is not part of the Docker image. The Docker build context contains only the Dockerfile and renderer script. If you built directly from GitHub without cloning, no local Git repository is necessary.

## Troubleshooting setup

- **`networkcheck` is not recognized:** reopen the terminal and check that the folder containing `networkcheck.bat` is in your Windows `PATH`.
- **The launcher cannot locate the script:** keep the `.bat` beside `networkcheck.ps1`, or use sibling `Batchfiles` and `NetworkCheck` folders.
- **PowerShell blocks the script:** check `Get-ExecutionPolicy -List`, verify the downloaded file and respect your organization's policy.
- **Docker image not found:** run one of the two build commands above.
- **Docker unavailable:** start Docker Desktop and select Linux containers.
- **Docker Desktop shows an image ID instead of `networkcheck:latest`:** the container may have been created from a raw image ID. The current launcher recreates its own stopped container from the tag when required. Do not delete unknown or running containers.
- **Some security checks are incomplete:** review `COLLECTION COVERAGE`. Use administrator privileges only if authorized and necessary.
- **Target DNS/TCP check fails:** this may be caused by firewall, DNS, proxy configuration or a target-specific issue rather than a general network outage.

## Safety and limitations

The scanner is **read-only** and makes no changes to Windows adapters, routes, services, registry, firewall or security settings. It contacts only the target explicitly supplied (or the default `example.com`) for DNS and one TCP connection. It does not discover network devices, scan subnets or test exploitation. Use it only on devices and targets you are authorized to assess.

Network checks can be incomplete without appropriate permissions. A successful DNS lookup or TCP connection does not establish TLS certificate validity or application health. Local listening sockets may be inaccessible, processes can exit during the scan, and identifying the process behind a listener does not always identify an individual service or device. SMB and LLMNR checks inspect configuration, not observed network traffic. This tool does **not** report verified CVEs or proof of compromise.

The renderer runs without a network connection, as a non-root process, with a read-only root filesystem, dropped capabilities and restricted mounts. The temporary scan input is isolated from saved reports. Temporary input is cleaned up after normal runs; abnormal termination may leave temporary files that can be removed once no scan is running.

Reports may contain hostnames, usernames, IP addresses, device names, running processes and security configuration. **Review reports before sharing them.** Actual reports and temporary working files are excluded from Git by `.gitignore` and from the Docker build context by `.dockerignore`.

Automated tests have covered normal/problematic/inconclusive synthetic cases, shared-service identification, PID 0, printer false positives, limited permissions and report formats. Some scenarios were tested with synthetic data rather than every physical device or installed service. Windows integration and Docker lifecycle tests should be repeated after modifying the container or staging behavior. Do not claim those new tests passed unless actually executed.

## License

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE).
