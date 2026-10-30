# NetworkCheck

**Read-only Windows network troubleshooting and security configuration checks, with a Docker-powered terminal report.**

NetworkCheck helps distinguish connectivity problems from potential security exposures. The scanner runs on the Windows host because Linux containers cannot directly access the host's Windows network configuration, registry, or services. A persistent, stopped Docker container formats results. No Windows settings are changed.

> **Security scope:** This is a **local configuration and exposure assessment**, not a comprehensive CVE, malware, vulnerability exploitation, internet perimeter, or subnet scanner. It does not identify unpatched CVEs by product version. Do not treat a clean result as proof of security.

## Quick start (Windows + Docker Desktop)

Requirements: Windows 10/11, Windows PowerShell 5.1 or PowerShell 7, and Docker Desktop set to Linux containers. Add the project folder (or an existing sibling `Batchfiles` folder) to your `PATH`.

The launcher is included beside the script. It also supports the existing sibling layout:

```text
NetworkCheck/
├── Dockerfile
├── networkcheck.ps1
├── .dockerignore
├── .gitignore
├── README.md
├── REVIEW.md
└── reports/
    └── .gitkeep
```

Build from `DockerProjects/NetworkCheck` (one time, and after source changes):

```powershell
docker build --no-cache -t networkcheck:latest .
```

Keep `networkcheck.bat` beside `networkcheck.ps1` and add that folder to your `PATH`, or copy the launcher into the existing sibling `DockerProjects/Batchfiles` folder. It finds the script relative to its own location and propagates the script's exit code.

Close/reopen the terminal, then run from **any directory**:

```powershell
networkcheck                            # Local network and example.com:443 test
networkcheck -o txt                     # Terminal + text report
networkcheck -o md                      # Terminal + Markdown report
networkcheck -o json                    # Terminal + structured JSON report
networkcheck -o md example.org          # Test a specific hostname
networkcheck -t 192.168.1.1 --port 443 # Test a device on your own network
networkcheck --help
```

Only `txt`, `md`, and `json` work after `-o`. The default performs a single DNS and TCP 443 connection test against `example.com`. Use `-t` to choose an authorized or internal destination. **Do not use NetworkCheck against systems you are not allowed to test.** No subnet scans or brute-force tests are performed.

Output files are placed in `NetworkCheck/reports` using timestamped names. Without `-o`, the report appears only in the terminal. Status colors are only applied to terminal output (not TXT/MD/JSON).

## What is checked?

| Area | Checks |
|---|---|
| Network interfaces | Active and inactive adapters, IPv4/IPv6 addresses, gateways, configured DNS servers, active IPv4/IPv6 routing table |
| Connectivity | Advisory ICMP reply from one gateway, bounded target name resolution, one TCP connection to the first resolved address |
| Local services | Listening TCP ports, process names where available (no external port scan) |
| Windows Firewall | Domain/Private/Public profile configuration |
| SMB | SMBv1 server configuration, whether client/server signing is required |
| Name resolution | LLMNR policy setting |
| Remote access | RDP enablement, RemoteRegistry service, potentially sensitive listening ports |

All findings include severity, confidence, concrete evidence, an explanation and non-destructive troubleshooting suggestions. `HIGH` confidence means a configuration or test result was directly observed; `MEDIUM` means the risk interpretation is indirect (for example, a conventional service port or an unconfigured LLMNR policy). Confidence does not measure exploitability. An open local port **does not mean** that the port is accessible from the internet; a security configuration finding **does not identify a CVE**.

## How to interpret the results

**Connectivity** describes the selected DNS/TCP test (`OK`, `ISSUES DETECTED`, `INCONCLUSIVE`). **Security** is a separate status (`NO CLEAR HIGH-RISK FINDINGS`, `REVIEW REQUIRED`, `INCOMPLETE`). A healthy network connection may still have security findings.

Failed collection is recorded as `FAILED` or `UNAVAILABLE`, with missing properties marked `INCOMPLETE`. Missing data stays unknown instead of becoming a false/disabled setting. Any missing security check makes the security summary `INCOMPLETE`; confirmed findings remain visible in ISSUES and the finding count. Missing network inventory makes connectivity `INCONCLUSIVE` unless a directly observed network issue already warrants `ISSUES DETECTED`. Blocked gateway ICMP alone does not mark connectivity unhealthy. Local-only networks do not necessarily require a default gateway.

Report sections:

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

The report includes device names, IP addresses, network configuration and process details. **Review before publishing or sharing**. `.gitignore` prevents generated reports from accidentally being committed by default.

## Docker lifecycle

The first run creates a container named `networkcheck`. After rendering the report, the container exits and remains visible as **Stopped** in Docker Desktop. Later runs reuse it; after a rebuild or renderer-policy update, the tool replaces only its own stopped, managed container. A foreign or running container with that name is never interrupted. No `docker compose`, `docker down`, or background service is needed.

The renderer uses the inspected image ID, a non-root user, no external network, a read-only root filesystem, dropped Linux capabilities, no-new-privileges, bounded resources and temporary `/tmp` storage. It mounts only `reports/.networkcheck-work` read-only. Previous reports are not mounted. Docker logging is disabled because the output contains report data. These options follow [Docker's container runtime controls](https://docs.docker.com/reference/cli/docker/container/run/).

DNS and TCP waits are each 3.5 seconds; gateway ICMP waits 1.2 seconds. Docker commands normally have a 15-second deadline, with 45 seconds allowed for rendering. A machine-wide mutex serializes runs. Cleanup attempts to stop the container and remove the temporary JSON even on errors; abrupt process termination or power loss can leave staging data behind. The persistent container remains stopped between runs. Docker cleanup failures are reported.

The CLI launches without an execution-policy bypass, and does not change the user's PowerShell execution policy. If your system blocks scripts, verify their source and follow your organization's policy.

## Troubleshooting setup

- `networkcheck` not recognized: check the batch folder is on your Windows `PATH`, then reopen the terminal.
- Docker not running: start Docker Desktop and use Linux containers.
- Image missing: run `docker build --no-cache -t networkcheck:latest .` from the NetworkCheck project folder.
- Some checks missing: run the terminal as administrator **only if authorized**, and review the collection notes.
- DNS or TCP test failed: this can be caused by a proxy or firewall rather than a general network outage.
- Windows PowerShell 5.1 blocked the script: do not automatically disable execution policies; review file trust and policy settings.

## Validation

The final development suite passed all 24 checks on Windows PowerShell 5.1.26100.9756 and PowerShell 7.6.9. It covered healthy, problematic and inconclusive synthetic cases, CLI validation, timeout handling, partial failures, legacy reports, complete listener inventory and TXT/Markdown/JSON consistency.

Docker integration verified the corrected renderer using a temporary read-only source mount into the user-built image, exact timestamp parity, two runs of the persistent `networkcheck` container, container reuse and shutdown, and temporary-input cleanup. No image was built by the development tests, and no private host assessment or external target probe was performed. A final manual Docker build is required to include the latest source fixes in the image.

The temporary test suite and synthetic fixtures were removed after validation at the owner's request. They are not part of the finalized project.

JSON schema version 2 retains existing report fields and adds `routes`, `checks`, finding `confidence`, coverage flags, the tested TCP address and the configured RDP port. `tcp_connected` can now be `null` when DNS failure prevents a connection attempt. `adapters` includes inactive interfaces while `summary.adapters` still counts active interfaces. TXT and Markdown include every collected listener. The renderer still accepts schema 1 reports, with missing confidence shown as legacy data.

## Limitations

- This is one target/address/port test. Other resolved addresses are listed but not contacted; no fallback address, proxy, HTTP, TLS or certificate validation is performed. A failed first address does not imply every address or the internet is unreachable.
- The Windows system resolver may use cache, the hosts file and configured name-resolution mechanisms. On .NET Framework, a DNS wait can time out while the underlying resolver finishes in the background.
- Local Windows inventory cmdlets have no enforced process-level deadline. Provider delays may extend total runtime beyond the probe timeouts. Missing permissions, absent modules, process exits and changing configuration can reduce coverage.
- Firewall profiles are effective profile configuration, not a rule-by-rule reachability analysis or third-party firewall assessment. Route metrics are reported without claiming which route Windows selected for the target. The advisory gateway need not be the route used for that target.
- SMBv1 assessment covers the server protocol setting, not the installed SMBv1 client optional feature. Signing settings are configuration observations, not captured SMB negotiation.
- RDP checks local enablement and configured TCP port, not every policy override, authentication setting or actual protocol handshake. LLMNR checks the policy registry value, not runtime traffic. RemoteRegistry service state does not establish remote accessibility.
- Privacy relies on local filesystem permissions. Reports may contain private information. `.gitignore` and the Docker build-context allowlist prevent normal accidental inclusion, but cannot prevent deliberate sharing. Do not force-add reports to source control.
- The official PowerShell base image currently uses `latest`; builds are not bit-for-bit reproducible. Image digest pinning and a deliberate update policy remain follow-up work.

## Background documentation

- [Microsoft: SMBv1 configuration](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Microsoft: SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: LLMNR Group Policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient)
- [Microsoft: Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)

No third-party Python libraries or package managers are required.
