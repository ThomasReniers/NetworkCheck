#requires -Version 5.1
<#
NetworkCheck - Windows read-only network and security diagnostics.
Windows collects data. Docker formats the JSON using this same script.
No changes to network settings, firewall, registry or services.
#>
$ErrorActionPreference = 'Stop'

function S($value) {
    if ($null -eq $value) { return '' }
    # Untrusted process/adapter/error strings must not inject terminal controls or report lines.
    return ([string]$value -replace '[\x00-\x1F\x7F-\x9F\u2028\u2029\u202A-\u202E\u2066-\u2069]', ' ')
}
function Add-Finding([System.Collections.ArrayList]$List, [string]$Category, [string]$Severity, [string]$Title, [string]$Evidence, [string]$Explanation, [string]$Action, [string]$Confidence='HIGH') {
    [void]$List.Add([ordered]@{ category=$Category; severity=$Severity; confidence=$Confidence; title=(S $Title); evidence=(S $Evidence); explanation=(S $Explanation); action=(S $Action) })
}
function Nullable-Bool($Value) {
    if ($null -eq $Value) { return $null }
    switch (([string]$Value).ToLowerInvariant()) { 'true' { return $true }; '1' { return $true }; 'false' { return $false }; '0' { return $false }; default { return $null } }
}
function Set-Check($Checks, [string]$Name, [string]$Status, [string]$Detail='') {
    $Checks[$Name] = [ordered]@{ status=$Status; detail=(S $Detail) }
}
function ConvertFrom-ReportJson([string]$Json) {
    # Keep the source timestamp and its original offset identical across report formats.
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { return ConvertFrom-Json -InputObject $Json -DateKind String }
    $report = ConvertFrom-Json -InputObject $Json
    if ($report.source.timestamp -is [DateTime] -or $report.source.timestamp -is [DateTimeOffset]) {
        # Older PowerShell 7 uses its bundled JSON.NET parser with automatic date conversion.
        # Read the original timestamp as a string using that same bundled library; no package is required.
        $stringReader = New-Object System.IO.StringReader($Json)
        $reader = [Newtonsoft.Json.JsonTextReader]::new($stringReader)
        try {
            $reader.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
            $document = [Newtonsoft.Json.Linq.JObject]::Load($reader)
            $report.source.timestamp = [string]$document['source']['timestamp']
        } finally { $reader.Close(); $stringReader.Dispose() }
    }
    return $report
}
function Is-Admin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function Read-Cmdlet([string]$Name, [scriptblock]$Action, [System.Collections.ArrayList]$Notes, $Checks) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        [void]$Notes.Add("$Name is unavailable on this Windows installation.")
        Set-Check $Checks $Name 'UNAVAILABLE' 'Command unavailable.'
        return $null
    }
    try {
        # Buffer results so a failed query cannot leak partial data as a successful check.
        $result = @(& $Action)
        Set-Check $Checks $Name 'OK'
        return $result
    } catch {
        Set-Check $Checks $Name 'FAILED' $_.Exception.Message
        [void]$Notes.Add(("{0} could not be read: {1}" -f $Name, (S $_.Exception.Message)))
        return $null
    }
}
function Read-RegistryValue([string]$Path, [string]$Name, [string]$CheckName, $Notes, $Checks) {
    try {
        $value = $null
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
            $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
            if ($null -ne $item.PSObject.Properties[$Name]) { $value = $item.$Name }
        }
        Set-Check $Checks $CheckName 'OK' $(if ($null -eq $value) { 'Not configured in this registry location.' } else { 'Registry value read.' })
        return $value
    } catch {
        Set-Check $Checks $CheckName 'FAILED' $_.Exception.Message
        [void]$Notes.Add(("{0} could not be read: {1}" -f $CheckName,(S $_.Exception.Message)))
        return $null
    }
}
function Start-NameResolution([string]$HostName) { return [System.Net.Dns]::GetHostAddressesAsync($HostName) }
function Resolve-One([string]$HostName, [int]$TimeoutMs=3500) {
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$ip)) {
        return [ordered]@{ succeeded=$null; addresses=@($ip.IPAddressToString); detail='IP address supplied; DNS not required.' }
    }
    try {
        $task = Start-NameResolution $HostName
        if (-not $task.Wait($TimeoutMs)) {
            return [ordered]@{ succeeded=$false; addresses=@(); detail='DNS resolution timed out.' }
        }
        $addresses = @($task.GetAwaiter().GetResult() | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique)
        return [ordered]@{ succeeded=($addresses.Count -gt 0); addresses=$addresses; detail='System resolver completed.' }
    } catch { return [ordered]@{ succeeded=$false; addresses=@(); detail=(S $_.Exception.GetBaseException().Message) } }
    # .NET Framework cannot cancel a pending system DNS lookup; only our wait is bounded.
}
function Ping-One([string]$HostName, [int]$TimeoutMs=1200) {
    $p = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $p.Send($HostName, $TimeoutMs)
        return [ordered]@{ target=$HostName; succeeded=($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success); status=(S $reply.Status); latency_ms= $(if ($reply.Status -eq 'Success') { [int]$reply.RoundtripTime } else { $null }) }
    } catch { return [ordered]@{ target=$HostName; succeeded=$false; status=(S $_.Exception.Message); latency_ms=$null } }
    finally { $p.Dispose() }
}
function Tcp-One([string]$HostName, [int]$Port, [int]$TimeoutMs=3500) {
    # Only resolved IPs are accepted here: do not trigger a second unbounded DNS lookup.
    $ip = [System.Net.IPAddress]::Parse($HostName)
    $c = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
    try {
        $ar = $c.BeginConnect($ip,$Port,$null,$null)
        try {
            $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs,$false)
            if (-not $ok) { return [ordered]@{ succeeded=$false; detail='Connection timed out' } }
            $c.EndConnect($ar)
            return [ordered]@{ succeeded=$true; detail='TCP connection established' }
        } finally { $ar.AsyncWaitHandle.Close() }
    } catch { return [ordered]@{ succeeded=$false; detail=(S $_.Exception.Message) } }
    finally { $c.Close(); $c.Dispose() }
}
function Get-LocalReport([string]$Target,[int]$Port) {
    $notes = New-Object System.Collections.ArrayList
    $issues = New-Object System.Collections.ArrayList
    $checks = [ordered]@{}
    $admin = Is-Admin
    $now = Get-Date
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { [void]$notes.Add('Operating system details unavailable.') }

    $rawAdapters = @(Read-Cmdlet 'Get-NetAdapter' { Get-NetAdapter -ErrorAction Stop } $notes $checks)
    $ipConfigs = @(Read-Cmdlet 'Get-NetIPConfiguration' { Get-NetIPConfiguration -All -ErrorAction Stop } $notes $checks)
    $rawRoutes = @(Read-Cmdlet 'Get-NetRoute' { Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop } $notes $checks)
    $routes = @($rawRoutes | Where-Object { $null -ne $_ } | Sort-Object InterfaceIndex,DestinationPrefix,NextHop | ForEach-Object {
        [ordered]@{ interface_index=[int]$_.InterfaceIndex; destination=(S $_.DestinationPrefix); next_hop=(S $_.NextHop); route_metric=[int]$_.RouteMetric; interface_metric=$_.InterfaceMetric; address_family=(S $_.AddressFamily) }
    })
    $adapters = @()
    foreach ($adapter in ($rawAdapters | Where-Object { $null -ne $_ } | Sort-Object ifIndex)) {
        $cfg = @($ipConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Select-Object -First 1)
        $ipv4 = @(); $ipv6 = @(); $gateways = @(); $dns = @()
        if ($cfg.Count -gt 0 -and $cfg[0]) {
            $ipv4 = @($cfg[0].IPv4Address | ForEach-Object { S $_.IPAddress } | Where-Object { $_ })
            $ipv6 = @($cfg[0].IPv6Address | ForEach-Object { S $_.IPAddress } | Where-Object { $_ })
            $gateways = @(@($cfg[0].IPv4DefaultGateway) + @($cfg[0].IPv6DefaultGateway) | ForEach-Object { S $_.NextHop } | Where-Object { $_ })
            $dns = @($cfg[0].DNSServer.ServerAddresses | ForEach-Object { S $_ } | Where-Object { $_ })
        }
        elseif ($adapter.Status -eq 'Up' -and $checks['Get-NetIPConfiguration'].status -eq 'OK') {
            Set-Check $checks 'Get-NetIPConfiguration' 'INCOMPLETE' 'An active adapter had no matching IP configuration.'
        }
        $adapters += [ordered]@{ name=(S $adapter.Name); description=(S $adapter.InterfaceDescription); index=[int]$adapter.ifIndex; status=(S $adapter.Status); ipv4=$ipv4; ipv6=$ipv6; gateway=$gateways; dns=$dns }
    }
    $activeAdapters = @($adapters | Where-Object { $_.status -eq 'Up' })
    if ($activeAdapters.Count -eq 0 -and $checks['Get-NetAdapter'].status -eq 'OK') { Add-Finding $issues 'NETWORK' 'HIGH' 'No active network adapter found' 'Windows did not report an adapter with Up status.' 'The host may not have an active network connection.' 'Check Wi-Fi/Ethernet, flight mode, and adapter state in Windows Settings.' }
    # ICMP is advisory; prefer IPv4, otherwise use an IPv6 gateway with its interface scope.
    $gateway = @($activeAdapters | ForEach-Object { $a=$_; $_.gateway | ForEach-Object { if ($_ -match '^fe80:' -and $_ -notmatch '%') { $_ + '%' + $a.index } else { $_ } } } | Sort-Object { $_ -match ':' } | Select-Object -Unique | Select-Object -First 1)
    $gatewayTest = $null
    if ($gateway.Count -gt 0) { $gatewayTest = Ping-One $gateway[0] }
    $resolved = Resolve-One $Target
    $dnsAddresses = @($resolved.addresses)
    $dnsSucceeded = $resolved.succeeded
    if ($dnsSucceeded -eq $false) {
        [void]$notes.Add(('Target name resolution: ' + $resolved.detail))
        Add-Finding $issues 'NETWORK' 'MEDIUM' 'Target name resolution failed' ("DNS lookup for {0}: {1}" -f $Target,$resolved.detail) 'The configured DNS servers, network connection, or domain name may be responsible.' 'Verify the hostname, DNS server addresses and network access. Compare with Resolve-DnsName on Windows.'
    }
    $tcp = [ordered]@{ succeeded=$null; detail='Not tested because no target address was resolved.' }
    $tcpAddress = $null
    if ($dnsAddresses.Count -gt 0) {
        # Exactly one connection attempt, to the first address returned by the Windows resolver.
        $tcpAddress = $dnsAddresses[0]
        $tcp = Tcp-One $tcpAddress $Port
    }
    if ($tcp.succeeded -eq $false) {
        Add-Finding $issues 'NETWORK' 'MEDIUM' 'TCP connectivity test failed' ("Connection to {0}:{1} failed: {2}" -f $Target,$Port,$tcp.detail) 'An outbound firewall, proxy, routing issue or the remote service could block the test; this is not proof that the entire internet is down.' 'Try another trusted target, review proxy/firewall rules, and check whether the destination actually listens on this port.'
    }
    $firewall = @(); $fwRaw = @(Read-Cmdlet 'Get-NetFirewallProfile' { Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop } $notes $checks)
    foreach ($f in $fwRaw) {
        if ($null -eq $f) { continue }
        $enabled = Nullable-Bool $f.Enabled
        $firewall += [ordered]@{ profile=(S $f.Name); enabled=$enabled; inbound=(S $f.DefaultInboundAction); outbound=(S $f.DefaultOutboundAction) }
        if ($null -eq $enabled) { Set-Check $checks 'Get-NetFirewallProfile' 'INCOMPLETE' 'A firewall profile did not report its enabled state.' }
        if ($enabled -eq $false) {
            Add-Finding $issues 'SECURITY' 'HIGH' ("Windows Firewall profile disabled: {0}" -f $f.Name) 'The active Windows Firewall policy reports Enabled=False.' 'Connections using this profile may have reduced host firewall protection; another firewall product may still protect the device.' 'Check your security policy and any third-party firewall before enabling the Windows Firewall profile.'
        }
    }

    if ($firewall.Count -lt 3 -and $checks['Get-NetFirewallProfile'].status -eq 'OK') { Set-Check $checks 'Get-NetFirewallProfile' 'INCOMPLETE' 'Fewer than three firewall profiles were returned.' }
    $smbServer = Read-Cmdlet 'Get-SmbServerConfiguration' { Get-SmbServerConfiguration -ErrorAction Stop } $notes $checks
    $smbClient = Read-Cmdlet 'Get-SmbClientConfiguration' { Get-SmbClientConfiguration -ErrorAction Stop } $notes $checks
    $smb = [ordered]@{ server_smb1=$null; server_signing_required=$null; client_signing_required=$null }
    if ($smbServer) {
        $smb.server_smb1 = Nullable-Bool $smbServer.EnableSMB1Protocol
        $smb.server_signing_required = Nullable-Bool $smbServer.RequireSecuritySignature
        if ($smb.server_smb1) { Add-Finding $issues 'SECURITY' 'HIGH' 'SMBv1 server protocol enabled' 'Get-SmbServerConfiguration reported EnableSMB1Protocol=True.' 'SMBv1 is a legacy file-sharing protocol with a significantly weaker security model.' 'Assess dependencies and disable SMBv1 using official Windows guidance after checking compatibility.' }
        if ($smb.server_signing_required -eq $false) { Add-Finding $issues 'SECURITY' 'LOW' 'SMB server signing not required' 'Get-SmbServerConfiguration reported RequireSecuritySignature=False.' 'When SMB signing is not enforced, certain on-path tampering protections may be weaker; requirements vary by environment.' 'Review SMB signing policy and application compatibility before requiring it.' }
    }
    if ($smbClient) {
        $smb.client_signing_required = Nullable-Bool $smbClient.RequireSecuritySignature
        if ($smb.client_signing_required -eq $false) { Add-Finding $issues 'SECURITY' 'LOW' 'SMB client signing not required' 'Get-SmbClientConfiguration reported RequireSecuritySignature=False.' 'Client connections may be accepted without mandatory signing depending on the server and negotiation.' 'Review SMB signing policy and file-server compatibility with your administrator.' }
    }
    if ($null -eq $smb.server_smb1 -or $null -eq $smb.server_signing_required) { if ($checks['Get-SmbServerConfiguration'].status -eq 'OK') { Set-Check $checks 'Get-SmbServerConfiguration' 'INCOMPLETE' 'Required SMB server properties were missing.' } }
    if ($null -eq $smb.client_signing_required) { if ($checks['Get-SmbClientConfiguration'].status -eq 'OK') { Set-Check $checks 'Get-SmbClientConfiguration' 'INCOMPLETE' 'Required SMB client property was missing.' } }

    $llmnrValue = Read-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 'LLMNR' $notes $checks
    if ($checks.LLMNR.status -eq 'OK' -and ($null -eq $llmnrValue -or $llmnrValue -ne 0)) { Add-Finding $issues 'SECURITY' 'LOW' 'LLMNR not disabled through Windows policy' $(if ($null -eq $llmnrValue) { 'DNS Client policy EnableMulticast is not configured.' } else { "DNS Client policy EnableMulticast=$llmnrValue." }) 'Link-local name resolution may allow spoofed local network responses in some environments. This policy does not prove runtime LLMNR activity.' 'If unnecessary in your environment, review the Group Policy setting to disable multicast name resolution.' 'MEDIUM' }

    $rdpDeny = Read-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 'RDP' $notes $checks
    $rdpEnabled = $null
    if ($null -ne $rdpDeny -and $rdpDeny -in @(0,1)) { $rdpEnabled = ($rdpDeny -eq 0) }
    elseif ($checks.RDP.status -eq 'OK') { Set-Check $checks 'RDP' 'INCOMPLETE' 'RDP enablement value missing or invalid.' }
    $rdpPort = Read-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber' 'RDP port' $notes $checks
    if ($null -eq $rdpPort -or $rdpPort -lt 1 -or $rdpPort -gt 65535) { if ($checks['RDP port'].status -eq 'OK') { Set-Check $checks 'RDP port' 'INCOMPLETE' 'RDP listener port missing or invalid.' }; $rdpPort=$null }

    $listen = @(); $rawListen = @(Read-Cmdlet 'Get-NetTCPConnection' { Get-NetTCPConnection -State Listen -ErrorAction Stop } $notes $checks)
    foreach ($c in ($rawListen | Where-Object { $null -ne $_ } | Sort-Object LocalPort,LocalAddress,OwningProcess -Unique)) {
        $name = ''
        try { $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop; $name = S $p.ProcessName } catch { $name = 'unknown' }
        $listen += [ordered]@{ address=(S $c.LocalAddress); port=[int]$c.LocalPort; process=$name; pid=[int]$c.OwningProcess; all_interfaces=(@('0.0.0.0','::') -contains (S $c.LocalAddress)) }
    }
    $ports = @($listen | Where-Object { $_.address -ne '::1' -and $_.address -notmatch '^127\.' })
    if ($rdpEnabled -eq $true) {
        $rdpListeners = @($listen | Where-Object { $null -ne $rdpPort -and $_.port -eq $rdpPort })
        Add-Finding $issues 'SECURITY' 'MEDIUM' 'Remote Desktop service enabled' ("RDP enablement is configured; configured port: {0}; matching local TCP listeners: {1}." -f $(if ($null -eq $rdpPort) { 'unknown' } else { $rdpPort }),$rdpListeners.Count) 'RDP access should be limited to trusted networks; enablement and local listening do not prove external reachability.' 'Check network firewall rules, VPN requirements, MFA, Network Level Authentication and authorized access.'
    }
    foreach ($item in $ports) {
        if ($item.port -in @(21,23,2375,5900)) {
            $sev = $(if ($item.port -in @(23,2375)) { 'HIGH' } else { 'MEDIUM' })
            Add-Finding $issues 'SECURITY' $sev ("Sensitive listening port: TCP {0}" -f $item.port) ("Listening on {0}:{1}, process {2}." -f $item.address,$item.port,$item.process) 'A non-loopback listener might be reachable from other devices. The port number does not establish the protocol, authentication, external access or a software vulnerability.' 'Identify the owning service, confirm it is needed, then restrict access and require encrypted/authenticated connections.' 'MEDIUM'
        }
    }
    $remoteRegistry = Read-Cmdlet 'Get-Service' { Get-Service -Name RemoteRegistry -ErrorAction Stop } $notes $checks
    if (-not $remoteRegistry -or -not $remoteRegistry.Status) { if ($checks['Get-Service'].status -eq 'OK') { Set-Check $checks 'Get-Service' 'INCOMPLETE' 'RemoteRegistry service state was not returned.' } }
    if ($remoteRegistry -and $remoteRegistry.Status -eq 'Running') { Add-Finding $issues 'SECURITY' 'MEDIUM' 'Remote Registry service running' 'Windows RemoteRegistry service is running.' 'Remote registry management increases the remote administration surface when reachable.' 'Confirm this is required and restrict access via firewall and account permissions.' }

    $securityStatus = 'NO CLEAR HIGH-RISK FINDINGS'
    if (@($issues | Where-Object { $_.category -eq 'SECURITY' }).Count -gt 0) { $securityStatus = 'REVIEW REQUIRED' }
    $securityKeys = @('Get-NetFirewallProfile','Get-SmbServerConfiguration','Get-SmbClientConfiguration','LLMNR','RDP','RDP port','Get-NetTCPConnection','Get-Service')
    $securityComplete = @($securityKeys | Where-Object { $checks[$_].status -ne 'OK' }).Count -eq 0
    if (-not $securityComplete) { $securityStatus = 'INCOMPLETE' }
    $networkStatus = 'OK'
    if (@($issues | Where-Object { $_.category -eq 'NETWORK' }).Count -gt 0) { $networkStatus = 'ISSUES DETECTED' }
    $networkComplete = @(@('Get-NetAdapter','Get-NetIPConfiguration','Get-NetRoute') | Where-Object { $checks[$_].status -ne 'OK' }).Count -eq 0
    if (-not $networkComplete -and $networkStatus -eq 'OK') { $networkStatus = 'INCONCLUSIVE' }
    return [ordered]@{
        schema_version=2
        source=[ordered]@{ computer=(S $env:COMPUTERNAME); os=$(if ($os) { S $os.Caption } else { 'Windows' }); timestamp=$now.ToString('o'); elevated=$admin; scanner='Windows PowerShell (read-only)' }
        target=[ordered]@{ hostname=$Target; port=$Port }
        summary=[ordered]@{ connectivity=$networkStatus; security=$securityStatus; adapters=$activeAdapters.Count; listening_ports=$listen.Count; network_issues=@($issues | Where-Object { $_.category -eq 'NETWORK' }).Count; security_findings=@($issues | Where-Object { $_.category -eq 'SECURITY' }).Count; connectivity_complete=$networkComplete; security_complete=$securityComplete }
        adapters=$adapters
        routes=$routes
        checks=$checks
        connectivity=[ordered]@{ gateway_ping=$gatewayTest; dns_resolved=$dnsSucceeded; dns_detail=$resolved.detail; addresses=$dnsAddresses; tcp_address=$tcpAddress; tcp_connected=$tcp.succeeded; tcp_detail=(S $tcp.detail) }
        listeners=@($listen)
        security=[ordered]@{ firewall=$firewall; smb=$smb; llmnr_policy_enable_multicast=$llmnrValue; rdp_enabled=$rdpEnabled; rdp_port=$rdpPort; remote_registry=$(if ($remoteRegistry) { S $remoteRegistry.Status } else { 'unknown' }) }
        issues=@($issues.ToArray())
        notes=@($notes.ToArray())
        disclaimer=@('This is a local Windows configuration review, not a comprehensive vulnerability or CVE scan.','No exploitation, subnet discovery, credential tests or external port scanning is performed.','A listening port is not proof of external reachability, and a configuration finding is not proof of compromise.','The destination specified by --target is contacted for DNS and one TCP connection.','The report may contain device names, IP addresses, processes and network details. Review before sharing.','Checks can be incomplete without administrator access. No Windows setting is changed.')
    }
}

function As-Lines($report) {
    $width=72; $out=New-Object System.Collections.ArrayList
    function Add-ReportLine([string]$v='') { [void]$out.Add((S $v)) }
    function Add-ReportHeading([string]$title) { Add-ReportLine ''; Add-ReportLine $title; Add-ReportLine ('-' * 72) }
    Add-ReportLine ('=' * $width); Add-ReportLine ('  NETWORKCHECK | {0}' -f $report.source.computer); Add-ReportLine ('=' * $width)
    Add-ReportHeading 'SUMMARY'
    Add-ReportLine ('  Connectivity      : [{0}]' -f $report.summary.connectivity)
    Add-ReportLine ('  Security          : [{0}]' -f $report.summary.security)
    Add-ReportLine ('  Active adapters   : {0}' -f $report.summary.adapters)
    Add-ReportLine ('  Listening ports   : {0}' -f $report.summary.listening_ports)
    Add-ReportLine ('  Network issues    : {0}' -f $report.summary.network_issues)
    Add-ReportLine ('  Security findings : {0}' -f $report.summary.security_findings)
    Add-ReportHeading 'SOURCE'
    Add-ReportLine ('  Computer   : {0}' -f $report.source.computer)
    Add-ReportLine ('  OS         : {0}' -f $report.source.os)
    Add-ReportLine ('  Date       : {0}' -f $report.source.timestamp)
    Add-ReportLine ('  Admin      : {0}' -f $(if ($report.source.elevated) { 'yes' } else { 'no' }))
    Add-ReportLine ('  Target     : {0}:{1}' -f $report.target.hostname,$report.target.port)
    Add-ReportHeading '1. NETWORK ADAPTERS'
    if (@($report.adapters).Count -eq 0) { Add-ReportLine '  No active network adapter data available.' }
    foreach ($a in $report.adapters) {
        Add-ReportLine ('  {0}' -f $a.name)
        Add-ReportLine ('    Status  : {0} (interface {1})' -f $a.status,$a.index)
        Add-ReportLine ('    IPv4    : {0}' -f $(if (@($a.ipv4).Count) { $a.ipv4 -join ', ' } else { 'not reported' }))
        Add-ReportLine ('    IPv6    : {0}' -f $(if (@($a.ipv6).Count) { $a.ipv6 -join ', ' } else { 'not reported' }))
        Add-ReportLine ('    Gateway : {0}' -f $(if (@($a.gateway).Count) { $a.gateway -join ', ' } else { 'none' }))
        Add-ReportLine ('    DNS     : {0}' -f $(if (@($a.dns).Count) { $a.dns -join ', ' } else { 'not reported' }))
    }
    if ($report.routes) {
        Add-ReportLine '  ROUTING (active IPv4/IPv6 routes):'
        foreach ($route in $report.routes) { Add-ReportLine ('    {0} via {1}; interface {2}; route metric {3}; interface metric {4}' -f $route.destination,$route.next_hop,$route.interface_index,$route.route_metric,$route.interface_metric) }
    }
    Add-ReportHeading '2. CONNECTIVITY'
    $g=$report.connectivity.gateway_ping
    Add-ReportLine ('  Gateway ping     : {0}' -f $(if ($null -eq $g) { 'not tested (gateway not reported)' } elseif ($g.succeeded) { 'responded, ' + $g.latency_ms + ' ms' } else { 'no reply (ICMP may be blocked)' }))
    Add-ReportLine ('  Target DNS       : {0}' -f $(if ($null -eq $report.connectivity.dns_resolved) { 'not required (IP address supplied)' } elseif ($report.connectivity.dns_resolved) { 'resolved' } else { 'failed' }))
    Add-ReportLine ('  Target addresses : {0}' -f $(if (@($report.connectivity.addresses).Count) { $report.connectivity.addresses -join ', ' } else { 'none' }))
    Add-ReportLine ('  DNS detail       : {0}' -f $report.connectivity.dns_detail)
    Add-ReportLine ('  Target TCP       : {0}' -f $(if ($null -eq $report.connectivity.tcp_connected) { 'not tested' } elseif ($report.connectivity.tcp_connected) { 'connected' } else { 'failed' }))
    Add-ReportLine ('  TCP address      : {0}' -f $report.connectivity.tcp_address)
    Add-ReportLine ('  Detail           : {0}' -f $report.connectivity.tcp_detail)
    Add-ReportHeading '3. LISTENING PORTS'
    Add-ReportLine ('  Found {0} local TCP listeners:' -f @($report.listeners).Count)
    if (@($report.listeners).Count -eq 0) { Add-ReportLine '  No listening TCP ports found or query unavailable.' }
    foreach ($item in $report.listeners) { Add-ReportLine ('  {0,-23} TCP {1,-5}  {2} (PID {3})' -f $item.address,$item.port,$item.process,$item.pid) }
    Add-ReportHeading '4. SECURITY & VULNERABILITY CHECKS'
    if (@($report.security.firewall).Count -gt 0) { foreach ($f in $report.security.firewall) { Add-ReportLine ('  Firewall {0,-8}: {1}' -f $f.profile,$(if ($null -eq $f.enabled) { 'unknown' } elseif ($f.enabled) { 'enabled' } else { 'DISABLED' })) } }
    else { Add-ReportLine '  Firewall         : not available' }
    $smb=$report.security.smb
    Add-ReportLine ('  SMBv1 server     : {0}' -f $(if ($null -eq $smb.server_smb1) { 'unknown' } elseif ($smb.server_smb1) { 'ENABLED' } else { 'disabled' }))
    Add-ReportLine ('  SMB server sign  : {0}' -f $(if ($null -eq $smb.server_signing_required) { 'unknown' } elseif ($smb.server_signing_required) { 'required' } else { 'not required' }))
    Add-ReportLine ('  SMB client sign  : {0}' -f $(if ($null -eq $smb.client_signing_required) { 'unknown' } elseif ($smb.client_signing_required) { 'required' } else { 'not required' }))
    Add-ReportLine ('  LLMNR policy     : {0}' -f $(if ($report.checks -and $report.checks.LLMNR.status -ne 'OK') { 'unknown (query failed)' } elseif ($report.security.llmnr_policy_enable_multicast -eq 0 -and $null -ne $report.security.llmnr_policy_enable_multicast) { 'disabled by policy' } else { 'not disabled by policy' }))
    Add-ReportLine ('  Remote Desktop   : {0}' -f $(if ($null -eq $report.security.rdp_enabled) { 'unknown' } elseif ($report.security.rdp_enabled) { 'enabled' } else { 'disabled' }))
    Add-ReportLine ('  Remote Registry  : {0}' -f $report.security.remote_registry)
    Add-ReportLine ('  RDP TCP port     : {0}' -f $(if ($null -eq $report.security.rdp_port) { 'unknown' } else { $report.security.rdp_port }))
    Add-ReportLine '  NOTE: Potential exposures, not verified CVEs or proof of compromise.'
    Add-ReportHeading '5. CONCLUSION'
    if ($report.summary.connectivity -eq 'OK') { Add-ReportLine '  Connectivity: [OK]'; Add-ReportLine '  The selected TCP destination was reachable from this computer.' }
    else { Add-ReportLine ('  Connectivity: [{0}]' -f $report.summary.connectivity); Add-ReportLine '  One or more connectivity checks could not be completed successfully.' }
    Add-ReportLine ('  Security    : [{0}]' -f $report.summary.security)
    if ($report.summary.security -eq 'REVIEW REQUIRED') { Add-ReportLine '  Configuration findings warrant review; no exploitation was performed.' }
    elseif ($report.summary.security -eq 'INCOMPLETE') { Add-ReportLine '  Some security checks were unavailable. Review available findings and collection coverage.' }
    else { Add-ReportLine '  No clear high-risk settings were detected in the inspected configuration.' }
    Add-ReportHeading '6. ISSUES'
    if (@($report.issues).Count -eq 0) { Add-ReportLine '  No clear issues found in the available checks.' }
    $i=0
    foreach ($issue in $report.issues) { $i++; Add-ReportLine ('  {0}. {1} | {2} | {3}' -f $i,$issue.category,$issue.severity,$issue.title); Add-ReportLine ('     Confidence: {0}' -f $(if ($issue.confidence) { $issue.confidence } else { 'not recorded (legacy report)' })); Add-ReportLine ('     Evidence: {0}' -f $issue.evidence); Add-ReportLine ('     Meaning : {0}' -f $issue.explanation) }
    Add-ReportHeading '7. TROUBLESHOOTING'
    if (@($report.issues).Count -eq 0) { Add-ReportLine '  No immediate change is indicated. If problems persist, collect exact error messages and check Event Viewer.' }
    $i=0; foreach ($issue in $report.issues) { $i++; Add-ReportLine ('  {0}. {1}: {2}' -f $i,$issue.title,$issue.action) }
    if ($report.checks) {
        Add-ReportHeading 'COLLECTION COVERAGE'
        foreach ($property in $report.checks.PSObject.Properties) {
            # Rendered JSON is a PSCustomObject. Direct in-process reports use a dictionary.
            if ($report.checks -is [System.Collections.IDictionary]) { break }
            Add-ReportLine ('  {0}: {1} {2}' -f $property.Name,$property.Value.status,$property.Value.detail)
        }
        if ($report.checks -is [System.Collections.IDictionary]) { foreach ($key in $report.checks.Keys) { Add-ReportLine ('  {0}: {1} {2}' -f $key,$report.checks[$key].status,$report.checks[$key].detail) } }
        Add-ReportLine '  For failed checks, retry only with authorized permissions; inspect the detail above.'
    }
    Add-ReportHeading 'DISCLAIMER'
    foreach ($d in $report.disclaimer) { Add-ReportLine ('  - ' + $d) }
    foreach ($note in $report.notes) { Add-ReportLine ('  - Collection note: ' + (S $note)) }
    Add-ReportLine ('=' * $width)
    return ($out -join "`n")
}
function As-Markdown($report) {
    # Technical sections are kept as a code block for alignment and readable diffs.
    $text = As-Lines $report
    $longest = 2
    foreach ($match in [regex]::Matches($text,'`+')) { if ($match.Length -gt $longest) { $longest=$match.Length } }
    $fence = '`' * ($longest + 1)
    return '# NetworkCheck' + "`n`n" + $fence + 'text' + "`n" + $text + "`n" + $fence + "`n"
}
function Terminal-Print([string]$ReportText) {
    foreach ($line in ($ReportText -split "`r?`n")) {
        $match=[regex]::Match($line,'^(.*?\[)(OK|WARNING|ISSUES DETECTED|INCONCLUSIVE|REVIEW REQUIRED|INCOMPLETE|NO CLEAR HIGH-RISK FINDINGS)(\].*)$')
        if (-not $match.Success) { Write-Host $line; continue }
        $color=switch ($match.Groups[2].Value) { 'OK' { 'Green' } 'NO CLEAR HIGH-RISK FINDINGS' { 'Green' } 'WARNING' {'Yellow'} 'REVIEW REQUIRED' {'Yellow'} 'ISSUES DETECTED' {'Red'} default {'Gray'} }
        Write-Host $match.Groups[1].Value -NoNewline
        Write-Host $match.Groups[2].Value -ForegroundColor $color -NoNewline
        Write-Host $match.Groups[3].Value
    }
}
function Native-Argument([string]$Value) {
    # Windows CommandLineToArgvW quoting, including quotes and trailing backslashes.
    return '"' + (($Value -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}
function Invoke-Docker([string[]]$DockerArgs, [int]$TimeoutMs=15000, [switch]$AllowFailure) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = @(Get-Command docker -CommandType Application -ErrorAction Stop)[0].Source
    $info.Arguments = ($DockerArgs | ForEach-Object { Native-Argument $_ }) -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $info.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            try { $process.Kill(); [void]$process.WaitForExit(3000) } catch { }
            throw ('Docker command timed out after {0} ms: {1}' -f $TimeoutMs,($DockerArgs -join ' '))
        }
        $result = [ordered]@{ exit_code=$process.ExitCode; stdout=$stdout.GetAwaiter().GetResult(); stderr=$stderr.GetAwaiter().GetResult() }
        if ($result.exit_code -ne 0 -and -not $AllowFailure) { throw ('Docker command failed: ' + (S $result.stderr).Trim()) }
        return $result
    } finally { $process.Dispose() }
}
function Docker-Text([string[]]$DockerArgs, [int]$TimeoutMs=15000) {
    return (Invoke-Docker -DockerArgs $DockerArgs -TimeoutMs $TimeoutMs).stdout
}
function Ensure-Container([string]$ReportsPath,[string]$ImageId) {
    if ($ReportsPath -match '[,"\r\n]') { throw 'The project path cannot contain commas, quotes or line breaks (Docker bind mount limitation).' }
    $inspection = Invoke-Docker -DockerArgs @('container','inspect','networkcheck') -AllowFailure
    if ($inspection.exit_code -eq 0) {
        $containers = ConvertFrom-Json -InputObject $inspection.stdout
        $container = @($containers)[0]
        if ($container.Config.Labels.'org.networkcheck.managed' -ne 'true') { throw 'A container named networkcheck already exists and is not managed by this tool.' }
        if ($container.State.Running) { throw 'The networkcheck container is currently running; refusing to interrupt it.' }
        $mounts = @($container.Mounts | Where-Object { $_.Destination -eq '/reports' -and $_.Type -eq 'bind' -and -not $_.RW })
        $sameSource = $false
        if ($mounts.Count -eq 1) {
            # Desktop may normalize a Windows source to its Linux VM path. Compare the label too.
            $source = $mounts[0].Source -replace '\\','/'
            $expected = $ReportsPath -replace '\\','/'
            $sameSource = ($source -ieq $expected -or $source -ieq ('/run/desktop/mnt/host/' + $expected.Substring(0,1).ToLowerInvariant() + $expected.Substring(2)))
        }
        $noNewPrivileges = @($container.HostConfig.SecurityOpt | Where-Object { $_ -in @('no-new-privileges:true','no-new-privileges=true','no-new-privileges') }).Count -gt 0
        $unexpectedMounts = @($container.Mounts | Where-Object { $_.Destination -ne '/reports' -and -not ($_.Type -eq 'tmpfs' -and $_.Destination -eq '/tmp') })
        $policyOK = ($container.Config.Labels.'org.networkcheck.renderer-policy' -eq '2' -and $container.HostConfig.NetworkMode -eq 'none' -and $container.HostConfig.ReadonlyRootfs -and $container.HostConfig.LogConfig.Type -eq 'none' -and $container.Config.User -eq '65532:65532' -and @($container.HostConfig.CapDrop) -contains 'ALL' -and -not $container.HostConfig.CapAdd -and $noNewPrivileges -and -not $container.HostConfig.Privileged -and $unexpectedMounts.Count -eq 0)
        if ($container.Image -eq $ImageId -and $container.Config.Labels.'org.networkcheck.reportspath' -ieq $ReportsPath -and $sameSource -and $policyOK) { return }
        [void](Docker-Text @('rm','networkcheck'))
    } elseif ($inspection.stderr -notmatch 'No such (object|container)') { throw ('Cannot inspect networkcheck container: ' + (S $inspection.stderr)) }
    $mount = 'type=bind,source={0},target=/reports,readonly' -f $ReportsPath
    [void](Docker-Text @('create','--name','networkcheck','--label','org.networkcheck.managed=true','--label','org.networkcheck.renderer-policy=2','--label',('org.networkcheck.reportspath=' + $ReportsPath),'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges=true','--user','65532:65532','--log-driver','none','--pids-limit','64','--memory','256m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--mount',$mount,$ImageId))
}
function Help {
@'
NetworkCheck - Windows network diagnostics and security configuration review

Usage:
  networkcheck                         Local network test against example.com:443
  networkcheck example.com             Choose a hostname/IP
  networkcheck --target example.com    Same, explicit option
  networkcheck -t 192.168.1.1 --port 443  Test a device on your own network
  networkcheck -o txt                  Terminal + TXT report
  networkcheck -o md                   Terminal + Markdown report
  networkcheck -o json                 Terminal + structured JSON report
  networkcheck --help

Only txt, md and json are supported. Saved reports: NetworkCheck/reports.
This is NOT an active subnet scanner or CVE/exploit scanner.
'@ | Write-Output
}

# Dot sourcing exposes helpers for offline regression tests without collecting host data.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $target='example.com'; $port=443; $format=''; $render=$false; $renderFile=''; $i=0; $targetSpecified=$false
    while ($i -lt $args.Count) {
        $arg=S $args[$i]
        switch -CaseSensitive ($arg) {
            '--render' { $render=$true; $i++; if ($i -ge $args.Count) { throw 'Missing render file.' }; $renderFile=S $args[$i] }
            '-t' { $i++; if ($i -ge $args.Count) { throw 'Missing target.' }; $target=S $args[$i]; $targetSpecified=$true }
            '--target' { $i++; if ($i -ge $args.Count) { throw 'Missing target.' }; $target=S $args[$i]; $targetSpecified=$true }
            '--port' { $i++; if ($i -ge $args.Count) { throw 'Missing port.' }; $portNumber=0; if (-not [int]::TryParse((S $args[$i]),[ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) { throw 'Port must be between 1 and 65535.' }; $port=$portNumber }
            '-o' { $i++; if ($i -ge $args.Count) { throw 'Missing output format: txt, md or json.' }; $format=(S $args[$i]).ToLowerInvariant(); if ($format -notin @('txt','md','json')) { throw 'Only txt, md and json are supported.' } }
            '--output' { $i++; if ($i -ge $args.Count) { throw 'Missing output format: txt, md or json.' }; $format=(S $args[$i]).ToLowerInvariant(); if ($format -notin @('txt','md','json')) { throw 'Only txt, md and json are supported.' } }
            { $_ -in @('-h','--help','-?') } { Help; exit 0 }
            default { if ($arg -notmatch '^-' -and -not $targetSpecified) { $target=$arg; $targetSpecified=$true } else { throw ("Unknown argument: {0}. Use networkcheck --help." -f $arg) } }
        }
        $i++
    }
    if ($render) {
        $report = ConvertFrom-ReportJson (Get-Content -LiteralPath $renderFile -Raw -Encoding UTF8)
        $txt = As-Lines $report
        $md = As-Markdown $report
        @{ text=$txt; markdown=$md } | ConvertTo-Json -Depth 6 -Compress | Write-Output
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($target) -or $target.Length -gt 253 -or $target -match '[\s\\/\x00-\x1F\x7F-\x9F]' -or $target -match '^-') { throw 'Target must be a hostname or IP address (no URL, path or port). Use --port separately.' }
    $kind = [System.Uri]::CheckHostName($target)
    if ($kind -eq [System.UriHostNameType]::Unknown) { throw 'Target is not a valid DNS hostname or IP address.' }
    if ($env:OS -ne 'Windows_NT') { throw 'Data collection requires Windows. Only --render is supported inside Linux containers.' }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker CLI not found. Install or start Docker Desktop.' }
    $osKind = (Docker-Text @('info','--format','{{.OSType}}')).Trim()
    if ($osKind -ne 'linux') { throw 'Switch Docker Desktop to Linux containers.' }
    try { $imageId = (Docker-Text @('image','inspect','networkcheck:latest','--format','{{.Id}}')).Trim() }
    catch { throw ('Cannot read Docker image. Run: docker build --no-cache -t networkcheck:latest . from the NetworkCheck folder. ' + $_.Exception.Message) }
    $reportsPath = Join-Path $PSScriptRoot 'reports'
    [void][System.IO.Directory]::CreateDirectory($reportsPath)
    $workPath = Join-Path $reportsPath '.networkcheck-work'
    $tempFile = Join-Path $workPath '.networkcheck-input.json'
    $mutex = New-Object System.Threading.Mutex($false,'Global\NetworkCheckCliLock')
    $locked=$false
    $started=$false
    try {
        try { $locked = $mutex.WaitOne(45000) } catch [System.Threading.AbandonedMutexException] { $locked=$true }
        if (-not $locked) { throw 'Another NetworkCheck scan is in progress.' }
        Write-Host ('Collecting network data for {0}:{1} ...' -f $target,$port)
        $report = Get-LocalReport $target $port
        [void][System.IO.Directory]::CreateDirectory($workPath)
        Ensure-Container -ReportsPath $workPath -ImageId $imageId
        [System.IO.File]::WriteAllText($tempFile,(ConvertTo-Json -InputObject $report -Depth 14 -Compress),[System.Text.UTF8Encoding]::new($false))
        $started=$true
        $raw = Docker-Text @('start','--attach','networkcheck') 45000
        $containers = ConvertFrom-Json -InputObject (Docker-Text @('inspect','networkcheck'))
        $state = @($containers)[0].State
        if ($state.Running -or $state.ExitCode -ne 0) { throw 'Container report rendering failed; no report was saved.' }
        $rendered = $raw | ConvertFrom-Json
        $plain=[string]$rendered.text
        if (-not $plain) { throw 'Container returned an empty report.' }
        Terminal-Print $plain
        if ($format) {
            $safe = ($target -replace '[^A-Za-z0-9._-]','-').Trim('-._')
            $filename='networkcheck-{0}-{1}.{2}' -f $safe,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'),$format
            $output=Join-Path $reportsPath $filename
            $content = switch ($format) {
                txt { $plain.TrimEnd()+"`r`n" }
                md { ([string]$rendered.markdown).TrimEnd()+"`r`n" }
                json { (ConvertTo-Json -InputObject $report -Depth 14)+"`r`n" }
            }
            [System.IO.File]::WriteAllText($output,$content,[System.Text.UTF8Encoding]::new($false))
            Write-Host ('Report saved: ' + $output)
        }
    } finally {
        try {
            if ($started) {
                try { [void](Docker-Text @('stop','--time','2','networkcheck') 10000) }
                catch { [Console]::Error.WriteLine(('NETWORKCHECK - WARNING: Could not confirm container stopped: ' + (S $_.Exception.Message))) }
            }
        } finally {
            if ($locked) { Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue; [void]$mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    }
} catch {
    [Console]::Error.WriteLine(('NETWORKCHECK - ERROR: ' + (S $_.Exception.Message)))
    exit 1
}
