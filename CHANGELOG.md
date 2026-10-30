# Changelog

## 0.2.0 - Assessment reliability and renderer isolation

- Fixed the report helper's `Get-History` alias collision and cross-version JSON parsing differences.
- Added coverage-aware summaries, nullable security values, confidence and actionable evidence.
- Bounded DNS/TCP and Docker waits; skipped TCP after failed resolution.
- Added routing, IPv6 gateways, inactive adapters and custom RDP-port evidence.
- Removed silent inventory truncation and checked specific-address sensitive listeners.
- Isolated Docker rendering, narrowed the input mount and disabled report logging.
- Added a portable batch launcher, synthetic fixtures and PowerShell 5.1/7 regression tests.
- Documented schema 2 compatibility and remaining limitations.
- Fixed multiple-match Docker executable lookup and timestamp conversion in older PowerShell 7 runtimes.
- Completed all 24 development and Docker integration checks on PowerShell 5.1 and 7.
- Removed the temporary tests folder and fixtures after validation at the owner's request; the launcher remains in the existing sibling folder.

## 0.1.0 - First test build

- Windows host scanner for active adapters, gateway, DNS and TCP connectivity.
- Local listening-port inventory and non-invasive security posture checks.
- Evidence-based issues with suggested, non-destructive troubleshooting.
- One persistent Docker container, stopped between scans.
- TXT, Markdown and JSON reports; terminal-only status colors.
- Explicit limitations: not a CVE or remote network scanner.
