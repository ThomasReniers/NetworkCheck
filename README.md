# NetworkCheck

**Read-only Windows network troubleshooting and security configuration checks, with a Docker-powered terminal report.**

NetworkCheck helps distinguish connectivity problems from potential security exposures. The scanner runs on the Windows host because Linux containers cannot directly access the host's Windows network configuration, registry, or services. A persistent, stopped Docker container formats results. No Windows settings are changed.

> **Security scope:** This is a **local configuration and exposure assessment**, not a comprehensive CVE, malware, vulnerability exploitation, internet perimeter, or subnet scanner. It does not identify unpatched CVEs by product version. Do not treat a clean result as proof of security.

## Quick start (Windows + Docker Desktop)

Requirements: Windows 10/11, Windows PowerShell 5.1 or PowerShell 7, and Docker Desktop set to Linux containers. Add the project folder to your `PATH`.

The launcher is included beside the script. It also supports the existing sibling layout:

```text
/NetworkCheck/
├── Dockerfile
├── networkcheck.ps1
├── .dockerignore
├── .gitignore
├── README.md
└── reports/
    └── .gitkeep
```

Build from `/NetworkCheck/` folder (one time, and after source changes):

```powershell
docker build --no-cache -t networkcheck:latest .
```

Keep `networkcheck.bat` beside `networkcheck.ps1` and add that folder to your `PATH`, or copy the launcher into a sibling folder in the same location as '/NetworkCheck/' and add that folder to your 'PATH'.
It finds the script relative to its own location and propagates the script's exit code.

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
| Local services | Listening TCP ports, executable/PID, associated Windows services, application metadata and explicit device-identification status (no external port scan) |
| Windows Firewall | Domain/Private/Public profile configuration |
| SMB | SMBv1 server configuration, whether client/server signing is required |
| Name resolution | LLMNR policy setting |
| Remote access | RDP enablement, RemoteRegistry service, potentially sensitive listening ports |

All findings include severity, confidence, concrete evidence, an explanation and non-destructive troubleshooting suggestions. `HIGH` confidence means a configuration or test result was directly observed; `MEDIUM` means the risk interpretation is indirect (for example, a conventional service port or an unconfigured LLMNR policy). Confidence does not measure exploitability. An open local port **does not mean** that the port is accessible from the internet; a security configuration finding **does not identify a CVE**.

### Listener identification

Section `3. LISTENING PORTS` shows aligned Address, Port, Process, Service, Application and Device fields for every listener. Process and executable metadata are cached for repeated sockets. Services are ordered by their internal name; all matching active services are listed when a process hosts several services. PID 0 is never treated as an application or matched to stopped services.

A service association uses the listener's owning PID and the local Windows service snapshot. `confirmed` means the service shares the observed process ID; it does not prove which hosted service owns an individual socket. Shared-process matches are explicitly `possible`. Service inventory failures produce `Not identified`, while a successful query with no matching service produces `N/A`. Process termination, inaccessible properties and observed PID-reuse conflicts retain the listener with an explanatory note.

Application identification prefers the executable's `ProductName` version resource. If absent, a unique most-specific installation-directory registration or a file description can supply a name labelled `possible`. Conflicting registration names are not arbitrarily resolved. The product is associated with the **host executable**, including for shared service hosts; it is not assumed to be the product of every hosted service. Version resources are self-reported, not publisher authentication. See [Microsoft's file version metadata](https://learn.microsoft.com/dotnet/api/system.diagnostics.fileversioninfo) and [installation registry fields](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key).

Device identification is deliberately conservative. Current process/service snapshots do not establish which particular device owns a local socket, so Device displays `N/A` and JSON explains `not_identified`. No device names are fabricated. Printer configuration and remote TCP printer endpoints are not treated as local listener ownership, and printer inventory or active device discovery is not performed merely to match a port number.

Identification reads local CIM snapshots and executable version resources without executing discovered programs. Installation registration is read only when needed; `Win32_Product` is not queried because its provider can trigger installer consistency checks and repairs ([Microsoft's explanation](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations)). Command lines, uninstall commands, license keys and full executable/install paths are not added to the report. Network-drive, UNC and reparse paths are skipped for metadata lookup. Protected processes, missing registrations and applications without useful metadata may remain unidentified; administrator privileges are not automatically requested.

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

**Service/application/device extension:** all 23 checks passed on Windows PowerShell 5.1.26100.9756 and PowerShell 7.6.9. Automated cases covered single/shared services, regular applications, PID 0, inaccessible/terminated processes, missing products, printer false-positive prevention, PID reuse, limited permissions, terminal/TXT/Markdown/JSON consistency, legacy reports and existing connectivity/security behavior. A separate local loopback TCP handshake also passed.

Actual Windows integration validated a Windows-reported listener against an independent process lookup and read product metadata from the current executable. Shared-service cases, printer exclusions and permission failures were validated with synthetic data; these results do not claim integration with every installed service, application or device. No active device discovery or external target probes were used.

Docker integration used the owner-built image on both PowerShell runtimes, compared rendered text and Markdown with the host renderer, and verified two runs reuse the persistent container, stop successfully and delete the temporary input. No image was built automatically. The temporary suite and fixtures were removed after all checks passed, as requested. The owner confirmed the final manual build, and the final project/diff privacy review passed. Git publication requires separate owner approval.

The prior **0.2 baseline** development suite passed all 24 checks on Windows PowerShell 5.1.26100.9756 and PowerShell 7.6.9. It covered healthy, problematic and inconclusive synthetic cases, CLI validation, timeout handling, partial failures, legacy reports, complete listener inventory and TXT/Markdown/JSON consistency.

That prior temporary test suite and its fixtures were also removed after validation at the owner's request.

JSON schema version 3 preserves the existing listener fields (`address`, `port`, `process`, `pid`, `all_interfaces`) and adds `executable`, `process_identification`, a `services` array, `service_identification`, `application`, `device` and `identification_notes`. Identification objects carry explicit status and evidence; application data also records its source and `process_executable` scope. A confirmed device requires direct ownership evidence; the current collector records devices as `not_identified`.

All schema 2 fields remain: `routes`, `checks`, finding `confidence`, coverage flags, the tested TCP address and configured RDP port. `tcp_connected` can be `null` when DNS failure prevents a connection attempt. `adapters` includes inactive interfaces while `summary.adapters` counts active interfaces. TXT and Markdown include every collected listener. The renderer still accepts schema 1 and 2 reports, with unavailable identification displayed as unknown rather than inferred. JSON consumers that strictly validate the version must accept schema 3 before using the new fields.

## Limitations

- This is one target/address/port test. Other resolved addresses are listed but not contacted; no fallback address, proxy, HTTP, TLS or certificate validation is performed. A failed first address does not imply every address or the internet is unreachable.
- The Windows system resolver may use cache, the hosts file and configured name-resolution mechanisms. On .NET Framework, a DNS wait can time out while the underlying resolver finishes in the background.
- Local Windows inventory cmdlets have no enforced process-level deadline. Provider delays may extend total runtime beyond the probe timeouts. Missing permissions, absent modules, process exits and changing configuration can reduce coverage.
- Listener service/process CIM requests use a 10-second operation timeout each; this is a provider timeout, not a guaranteed whole-scan deadline. Registry and metadata reads can add time. Snapshots are not atomic: creation times reject observed PID-reuse conflicts but cannot rule out every race. The application's resources on disk may also have changed since the process started. Installation-registration fallback covers the machine and current user's standard uninstall registry views, not every package system or other users' registrations.
- On 64-bit Windows, use 64-bit PowerShell for application metadata. A 32-bit host retains listener/service collection but skips executable metadata to avoid identifying a different binary through filesystem redirection.
- Firewall profiles are effective profile configuration, not a rule-by-rule reachability analysis or third-party firewall assessment. Route metrics are reported without claiming which route Windows selected for the target. The advisory gateway need not be the route used for that target.
- SMBv1 assessment covers the server protocol setting, not the installed SMBv1 client optional feature. Signing settings are configuration observations, not captured SMB negotiation.
- RDP checks local enablement and configured TCP port, not every policy override, authentication setting or actual protocol handshake. LLMNR checks the policy registry value, not runtime traffic. RemoteRegistry service state does not establish remote accessibility.
- Privacy relies on local filesystem permissions. Reports may contain private information. `.gitignore` and the Docker build-context allowlist prevent normal accidental inclusion, but cannot prevent deliberate sharing. Do not force-add reports to source control.
- The official PowerShell base image currently uses `latest`; builds are not bit-for-bit reproducible. Image digest pinning and a deliberate update policy remain follow-up work.

No third-party Python libraries or package managers are required.
