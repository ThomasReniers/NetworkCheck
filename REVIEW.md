# NetworkCheck development review

Reviewed all original project files, ignore rules and the existing sibling batch launcher. The reports directory contained only its placeholder. This checkout has no `.git` repository metadata; no commits or pushes were performed. The single host/renderer script, Dockerfile, batch-launcher interface and manual build workflow are preserved.

## Priorities and changes

| Priority | Original issue | Result |
|---|---|---|
| P1 | The `H` report helper collides with PowerShell's `h` alias for `Get-History`, breaking rendering. | Replaced abbreviated report helpers with explicit names; actual render-entry tests cover both PowerShell versions. |
| P1 | Failed adapter/registry reads could become configuration findings; incomplete SMB properties became false; a few successful checks could conceal missing security coverage. | Explicit check coverage and nullable booleans distinguish failed, unavailable, incomplete and successful collection. Confirmed findings survive incomplete coverage. |
| P1 | Synchronous DNS had no explicit deadline, then TCP repeated hostname resolution even after DNS failure. | Bounded asynchronous resolution, no TCP after failed DNS, exactly one TCP attempt to the first resolved IP, with the tested address recorded. |
| P1 | Renderer ran with default container privileges/network and mounted all saved reports; Docker logs retained report output. | Narrow staging mount, no network, non-root user, read-only root, capability restrictions, disabled logging and resource limits. Managed-container policy and image/mount checks control reuse. |
| P1 | Native Docker calls had no deadline; concurrent sessions could race; failed rendering could leave a running container. | Bounded subprocess wrapper, global mutex, ownership checks, cleanup stop attempt and temporary-file removal. Docker lifecycle integration passed on both PowerShell runtimes. |
| P1 | Untrusted text could inject terminal controls; Markdown fences could be closed by embedded backticks. | Sanitize collected text and rendered lines; choose a fence longer than any embedded run of backticks. Only status indicators receive terminal colors. |
| P2 | No confidence classification, routing inventory, inactive adapters or custom RDP port support. | Added confidence and evidence context, IPv4/IPv6 routes and gateways, inactive adapters, scoped IPv6 gateway ping and configured RDP-port correlation. |
| P2 | Sensitive listeners bound to a specific address were missed, and listener/adapter caps silently omitted data. | Review non-loopback listeners; retain complete collected inventories in JSON/TXT/Markdown. Port-based risks explicitly remain hypotheses about services. |
| P2 | No regression suite or samples. | Validated with a temporary PowerShell suite and three synthetic fixtures, then removed the tests folder at the owner's request. The existing sibling batch launcher is maintained by the owner. |
| P2 | PowerShell JSON date parsing and top-level JSON array behavior differed between versions. | Preserve exact timestamp strings on older and newer PowerShell 7; normalize Docker inspect arrays explicitly. |
| P1 | Docker executable lookup can return both the Windows executable and an extensionless companion file. | Select the first executable match instead of joining multiple paths; verified with a regression case and real Docker calls. |

## Validation and follow-up

All 24 development checks passed on Windows PowerShell 5.1.26100.9756 and PowerShell 7.6.9. They covered classification, partial failures, DNS and subprocess deadlines, loopback sockets, IPv6 gateways, custom RDP ports, inventory completeness, output equivalence, control characters, CLI validation and container ownership/reuse. Real Docker tests verified the corrected renderer using a temporary read-only source mount into the owner-built image, timestamp parity, two persistent-container runs, shutdown and input cleanup. No real host assessment or external target probe was used. The temporary tests folder and fixtures were removed after validation at the owner's request.

Next priorities:

1. The owner performs the final manual Docker build to include the latest source fixes. Integration testing already passed on both PowerShell runtimes from the existing project path containing spaces and non-ASCII characters.
2. Bound local inventory providers in an isolated worker process, preserving partial results and compatibility without changing execution policy.
3. Pin and regularly update the official image digest; validate image upgrades with the same synthetic cases.
4. Extend evidence coverage for the SMBv1 client feature, effective RDP policy/NLA and active firewall profiles. Keep policy observations separate from proof of reachability or exploitability.

See README for scope, schema changes, timeout semantics and privacy limitations. No Windows or network configuration changes are made by the CLI. The reviewed script's downloaded-file marker was removed during development to run it under the existing `RemoteSigned` policy; the policy itself was not changed.
