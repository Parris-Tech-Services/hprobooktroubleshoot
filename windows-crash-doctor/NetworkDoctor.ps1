[CmdletBinding()]
param(
    [ValidateSet('Diagnose','Refresh')]
    [string]$Mode = 'Diagnose',
    [string]$OutputDirectory = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Windows Crash Doctor Results'),
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Check {
    param(
        [string]$Name,
        [ValidateSet('PASS','WARN','FAIL','INFO','UNKNOWN')]
        [string]$Status,
        [string]$Detail,
        $Evidence = $null
    )
    [ordered]@{
        name = $Name
        status = $Status
        detail = $Detail
        evidence = $Evidence
    }
}

function Test-PingTarget {
    param([string]$Target)
    try { return [bool](Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction Stop) }
    catch { return $false }
}

function Test-DnsTarget {
    param([string]$Name = 'google.com', [string]$Server)
    try {
        $params = @{
            Name = $Name
            Type = 'A'
            DnsOnly = $true
            QuickTimeout = $true
            ErrorAction = 'Stop'
        }
        if ($Server) { $params.Server = $Server }
        $result = Resolve-DnsName @params | Where-Object { $_.IPAddress } | Select-Object -First 1
        [ordered]@{
            success = [bool]$result
            address = if ($result) { [string]$result.IPAddress } else { $null }
            error = $null
        }
    }
    catch {
        [ordered]@{ success = $false; address = $null; error = $_.Exception.Message }
    }
}

function Test-HttpsTarget {
    param(
        [string]$Url = 'https://www.google.com',
        [ValidateSet('Any','IPv4','IPv6')]
        [string]$Family = 'Any'
    )

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        try {
            $request = [System.Net.HttpWebRequest]::Create($Url)
            $request.Method = 'HEAD'
            $request.Timeout = 8000
            $response = $request.GetResponse()
            $code = [int]$response.StatusCode
            $response.Close()
            return [ordered]@{ success = ($code -ge 200 -and $code -lt 500); statusCode = $code; error = $null }
        }
        catch {
            return [ordered]@{ success = $false; statusCode = $null; error = $_.Exception.Message }
        }
    }

    $args = @('-sS','-I','--max-time','8','-o','NUL','-w','%{http_code}')
    if ($Family -eq 'IPv4') { $args += '-4' }
    elseif ($Family -eq 'IPv6') { $args += '-6' }
    $args += $Url

    try {
        $output = & $curl.Source @args 2>&1
        $exitCode = $LASTEXITCODE
        $text = ($output | Out-String).Trim()
        $match = [regex]::Match($text, '(?<code>\d{3})\s*$')
        $code = if ($match.Success) { [int]$match.Groups['code'].Value } else { $null }
        [ordered]@{
            success = ($exitCode -eq 0 -and $null -ne $code -and $code -ge 200 -and $code -lt 500)
            statusCode = $code
            error = if ($exitCode -eq 0) { $null } else { $text }
        }
    }
    catch {
        [ordered]@{ success = $false; statusCode = $null; error = $_.Exception.Message }
    }
}

function Get-Classification {
    param(
        [bool]$HasConnectedAdapter,
        [bool]$HasApipa,
        [bool]$HasDuplicateAddress,
        [bool]$HasGateway,
        [bool]$InternetPing,
        [bool]$CurrentDns,
        [bool]$DirectDns,
        [bool]$Https
    )

    if (-not $HasConnectedAdapter) {
        return [ordered]@{
            classification = 'No connected network adapter'
            severity = 'High'
            summary = 'Windows cannot see a connected Ethernet or Wi-Fi path.'
            nextAction = 'Check link state, cable/Wi-Fi association and adapter status before changing DNS or browser settings.'
        }
    }
    if ($HasDuplicateAddress) {
        return [ordered]@{
            classification = 'Duplicate IP address conflict'
            severity = 'High'
            summary = 'Windows has evidence that another device or network component is answering for an address assigned to this PC.'
            nextAction = 'Identify the conflicting MAC/device from Event 4199 and ARP/neighbour evidence. Do not hide the fault with a random static IP.'
        }
    }
    if ($HasApipa) {
        return [ordered]@{
            classification = 'DHCP/addressing failure'
            severity = 'High'
            summary = 'The active adapter has a 169.254.x.x APIPA address, which normally means DHCP did not supply a usable IPv4 lease.'
            nextAction = 'Check DHCP reachability and the upstream router/switch/mesh path, then use Refresh DHCP + DNS if the network should be automatic.'
        }
    }
    if (-not $HasGateway) {
        return [ordered]@{
            classification = 'No default gateway'
            severity = 'High'
            summary = 'The active adapter has no usable IPv4 default gateway.'
            nextAction = 'Check DHCP/static configuration and compare the gateway with a working device on the same network.'
        }
    }
    if (-not $InternetPing -and -not $Https) {
        return [ordered]@{
            classification = 'Upstream connectivity failure'
            severity = 'High'
            summary = 'The PC has local addressing but cannot reach a public IP or complete an HTTPS request.'
            nextAction = 'Check gateway reachability, router/ISP state, VLAN/firewall path and whether other devices on the same network are affected.'
        }
    }
    if (-not $CurrentDns -and $DirectDns) {
        return [ordered]@{
            classification = 'DNS resolver/filter failure'
            severity = 'High'
            summary = 'Direct public DNS works but the DNS resolver configured on this PC does not.'
            nextAction = 'Inspect the configured DNS server and any local DNS/filter service listening on loopback before changing network hardware.'
        }
    }
    if (-not $CurrentDns -and -not $DirectDns -and $InternetPing) {
        return [ordered]@{
            classification = 'DNS path failure'
            severity = 'High'
            summary = 'Raw IP connectivity works but DNS resolution is failing through both the configured resolver and direct public resolvers.'
            nextAction = 'Check DNS interception, firewall/security policy, VPN/filter software and upstream DNS reachability.'
        }
    }
    if ($CurrentDns -and -not $Https) {
        return [ordered]@{
            classification = 'HTTPS/TLS/filtering failure'
            severity = 'Medium'
            summary = 'Addressing and DNS work, but HTTPS requests fail.'
            nextAction = 'Check TLS inspection, security/filter software, VPNs, system clock, certificates and browser/network filtering.'
        }
    }

    [ordered]@{
        classification = 'Windows network path healthy'
        severity = 'None'
        summary = 'Addressing, DNS and HTTPS tests passed from Windows.'
        nextAction = 'If an app or browser still fails, focus on that app, browser profile/session, extension, QUIC/proxy behaviour or local security integration rather than the basic internet link.'
    }
}

function Invoke-SelfTest {
    $cases = @(
        @{ name='apipa'; values=@($true,$true,$false,$false,$false,$false,$false,$false); expected='DHCP/addressing failure' },
        @{ name='duplicate'; values=@($true,$false,$true,$true,$true,$true,$true,$true); expected='Duplicate IP address conflict' },
        @{ name='dns'; values=@($true,$false,$false,$true,$true,$false,$true,$true); expected='DNS resolver/filter failure' },
        @{ name='https'; values=@($true,$false,$false,$true,$true,$true,$true,$false); expected='HTTPS/TLS/filtering failure' },
        @{ name='healthy'; values=@($true,$false,$false,$true,$true,$true,$true,$true); expected='Windows network path healthy' }
    )
    foreach ($case in $cases) {
        $r = Get-Classification $case.values[0] $case.values[1] $case.values[2] $case.values[3] $case.values[4] $case.values[5] $case.values[6] $case.values[7]
        if ($r.classification -ne $case.expected) {
            throw "Network Doctor self-test '$($case.name)' failed: expected '$($case.expected)', got '$($r.classification)'."
        }
    }
    Write-Output 'Network Doctor self-test passed.'
}

if ($SelfTest) {
    Invoke-SelfTest
    exit 0
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

$activeAdapter = $null
if ($defaultRoute) {
    $activeAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
}
if (-not $activeAdapter) {
    $activeAdapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object Status -eq 'Up' |
        Sort-Object ifIndex |
        Select-Object -First 1
}

if ($Mode -eq 'Refresh') {
    if (-not $activeAdapter) { throw 'No connected adapter was found to refresh.' }

    Clear-DnsClientCache -ErrorAction SilentlyContinue
    & ipconfig.exe /flushdns | Out-Null

    $ipInterface = Get-NetIPInterface -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ipInterface -and $ipInterface.Dhcp -eq 'Enabled') {
        & ipconfig.exe /release "$($activeAdapter.Name)" | Out-Null
        Start-Sleep -Seconds 1
        & ipconfig.exe /renew "$($activeAdapter.Name)" | Out-Null
    }

    Write-Output "Refreshed DNS cache and DHCP lease for $($activeAdapter.Name)."
    exit 0
}

$checks = New-Object System.Collections.Generic.List[object]
$adapterRecords = @()

foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
    $ipv4 = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' })
    $iface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $adapterRecords += [ordered]@{
        name = $adapter.Name
        description = $adapter.InterfaceDescription
        status = [string]$adapter.Status
        macAddress = $adapter.MacAddress
        linkSpeed = [string]$adapter.LinkSpeed
        interfaceIndex = [int]$adapter.ifIndex
        dhcp = if ($iface) { [string]$iface.Dhcp } else { $null }
        ipv4 = @($ipv4 | ForEach-Object {
            [ordered]@{
                address = $_.IPAddress
                prefixLength = $_.PrefixLength
                addressState = [string]$_.AddressState
                prefixOrigin = [string]$_.PrefixOrigin
                suffixOrigin = [string]$_.SuffixOrigin
            }
        })
    }
}

$connected = [bool]$activeAdapter
$activeConfig = if ($activeAdapter) { Get-NetIPConfiguration -InterfaceIndex $activeAdapter.ifIndex -ErrorAction SilentlyContinue } else { $null }
$activeInterface = if ($activeAdapter) { Get-NetIPInterface -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue } else { $null }
$activeAddresses = if ($activeAdapter) {
    @(Get-NetIPAddress -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' })
} else { @() }

$hasApipa = [bool]($activeAddresses | Where-Object { $_.IPAddress -like '169.254.*' })
$hasDuplicateAddress = [bool]($activeAddresses | Where-Object { [string]$_.AddressState -eq 'Duplicate' })
$gateway = if ($activeConfig -and $activeConfig.IPv4DefaultGateway) { [string]$activeConfig.IPv4DefaultGateway.NextHop } else { $null }
$hasGateway = -not [string]::IsNullOrWhiteSpace($gateway)

$connectedStatus = if ($connected) { 'PASS' } else { 'FAIL' }
$connectedDetail = if ($connected) { "$($activeAdapter.Name) - $($activeAdapter.InterfaceDescription) - $($activeAdapter.LinkSpeed)" } else { 'No connected adapter found.' }
$checks.Add((New-Check 'Connected adapter' $connectedStatus $connectedDetail))

if ($activeInterface) {
    $ipv4Status = if ($hasApipa) { 'FAIL' } elseif ($activeAddresses.Count -gt 0) { 'PASS' } else { 'FAIL' }
    $ipv4Detail = if ($hasApipa) {
        'APIPA 169.254.x.x detected.'
    } elseif ($activeAddresses.Count -gt 0) {
        (($activeAddresses | ForEach-Object IPAddress) -join ', ') + " | DHCP $($activeInterface.Dhcp)"
    } else {
        'No usable IPv4 address found.'
    }
    $checks.Add((New-Check 'IPv4 configuration' $ipv4Status $ipv4Detail))
}

if ($hasGateway) {
    $gatewayPing = Test-PingTarget $gateway
    $gatewayStatus = if ($gatewayPing) { 'PASS' } else { 'WARN' }
    $gatewayDetail = if ($gatewayPing) { "$gateway | ping passed" } else { "$gateway | ping did not reply" }
    $checks.Add((New-Check 'Default gateway' $gatewayStatus $gatewayDetail))
}
else {
    $gatewayPing = $false
    $checks.Add((New-Check 'Default gateway' 'FAIL' 'No IPv4 default gateway is configured.'))
}

$dhcpService = Get-Service Dhcp -ErrorAction SilentlyContinue
if ($dhcpService) {
    $dhcpStatus = if ($dhcpService.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
    $checks.Add((New-Check 'DHCP Client service' $dhcpStatus "Status: $($dhcpService.Status)"))
}

$internetPing = Test-PingTarget '8.8.8.8'
$internetStatus = if ($internetPing) { 'PASS' } else { 'WARN' }
$internetDetail = if ($internetPing) { '8.8.8.8 ping passed' } else { '8.8.8.8 ping failed or was blocked' }
$checks.Add((New-Check 'Public IP reachability' $internetStatus $internetDetail))

$dnsServers = if ($activeAdapter) {
    @((Get-DnsClientServerAddress -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
} else { @() }

$currentDns = Test-DnsTarget
$currentDnsStatus = if ($currentDns.success) { 'PASS' } else { 'FAIL' }
$currentDnsDetail = if ($currentDns.success) { "google.com -> $($currentDns.address)" } else { "Failed: $($currentDns.error)" }
$checks.Add((New-Check 'Configured DNS resolution' $currentDnsStatus $currentDnsDetail $dnsServers))

$directDns1 = Test-DnsTarget -Server '1.1.1.1'
$directDns8 = Test-DnsTarget -Server '8.8.8.8'
$directDns = [bool]($directDns1.success -or $directDns8.success)
$directStatus = if ($directDns) { 'PASS' } else { 'WARN' }
$checks.Add((New-Check 'Direct public DNS' $directStatus "1.1.1.1: $($directDns1.success); 8.8.8.8: $($directDns8.success)"))

$loopbackDns = @($dnsServers | Where-Object { $_ -eq '::1' -or $_ -like '127.*' })
$dnsListeners = @()
if ($loopbackDns.Count -gt 0) {
    $allServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
    foreach ($endpoint in @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)) {
        $proc = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
        $svc = $allServices | Where-Object ProcessId -eq $endpoint.OwningProcess | Select-Object -First 1
        $dnsListeners += [ordered]@{
            localAddress = $endpoint.LocalAddress
            pid = $endpoint.OwningProcess
            process = if ($proc) { $proc.ProcessName } else { $null }
            service = if ($svc) { $svc.Name } else { $null }
            serviceDisplayName = if ($svc) { $svc.DisplayName } else { $null }
            servicePath = if ($svc) { $svc.PathName } else { $null }
        }
    }
    $listenerNames = @()
    foreach ($listener in $dnsListeners) {
        if ($listener.serviceDisplayName) { $listenerNames += $listener.serviceDisplayName }
        elseif ($listener.process) { $listenerNames += $listener.process }
    }
    $loopStatus = if ($currentDns.success) { 'INFO' } else { 'FAIL' }
    $loopDetail = if ($listenerNames.Count -gt 0) {
        'Loopback DNS is configured. Listener: ' + ($listenerNames -join ', ')
    } else {
        'Loopback DNS is configured but no UDP/53 owner was identified.'
    }
    $checks.Add((New-Check 'Local DNS/filter service' $loopStatus $loopDetail $dnsListeners))
}

$httpsAny = Test-HttpsTarget
$https4 = Test-HttpsTarget -Family IPv4
$https6 = Test-HttpsTarget -Family IPv6
$checks.Add((New-Check 'HTTPS' $(if ($httpsAny.success) { 'PASS' } else { 'FAIL' }) "google.com HTTPS status: $($httpsAny.statusCode)"))
$checks.Add((New-Check 'HTTPS IPv4' $(if ($https4.success) { 'PASS' } else { 'WARN' }) "IPv4 HTTPS status: $($https4.statusCode)"))
$checks.Add((New-Check 'HTTPS IPv6' 'INFO' "IPv6 HTTPS success: $($https6.success); status: $($https6.statusCode)"))

$tcp443 = $false
try {
    $tcp443 = [bool](Test-NetConnection -ComputerName 'github.com' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
}
catch { $tcp443 = $false }
$checks.Add((New-Check 'TCP 443' $(if ($tcp443) { 'PASS' } else { 'WARN' }) "github.com:443 $(if ($tcp443) { 'reachable' } else { 'not reachable' })"))

$duplicateEvents = @()
try {
    foreach ($evt in @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=4199; StartTime=(Get-Date).AddDays(-30) } -ErrorAction Stop | Select-Object -First 50)) {
        $ip = $null
        $mac = $null
        $m = [regex]::Match($evt.Message, '(?i)IP address\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3}).*?hardware address\s+(?<mac>[0-9A-F-]{11,})')
        if ($m.Success) {
            $ip = $m.Groups['ip'].Value
            $mac = $m.Groups['mac'].Value.ToUpperInvariant()
        }
        $duplicateEvents += [ordered]@{
            timeCreated = $evt.TimeCreated.ToString('o')
            ipAddress = $ip
            macAddress = $mac
            message = $evt.Message
        }
    }
}
catch {
    $checks.Add((New-Check 'Duplicate-IP event log' 'UNKNOWN' "System Event 4199 could not be read: $($_.Exception.Message)"))
}

if ($duplicateEvents.Count -gt 0) {
    $recentCutoff = (Get-Date).AddHours(-1)
    $recentDuplicate = @($duplicateEvents | Where-Object { [datetime]$_.timeCreated -ge $recentCutoff })
    $multiClaimMac = @(
        $duplicateEvents |
        Where-Object macAddress |
        Group-Object macAddress |
        Where-Object { (@($_.Group | Select-Object -ExpandProperty ipAddress -Unique)).Count -ge 2 } |
        ForEach-Object Name
    )
    if ($recentDuplicate.Count -gt 0) { $hasDuplicateAddress = $true }
    $detail = "$($duplicateEvents.Count) conflict event(s) in 30 days"
    if ($multiClaimMac.Count -gt 0) { $detail += '; MAC(s) seen claiming multiple IPs: ' + ($multiClaimMac -join ', ') }
    $dupStatus = if ($recentDuplicate.Count -gt 0) { 'FAIL' } else { 'WARN' }
    $checks.Add((New-Check 'Duplicate-IP history' $dupStatus $detail $duplicateEvents))
}
else {
    $checks.Add((New-Check 'Duplicate-IP history' 'PASS' 'No Event 4199 address-conflict records found in the last 30 days.'))
}

$neighbors = @()
if ($activeAdapter) {
    foreach ($n in @(Get-NetNeighbor -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' })) {
        $neighbors += [ordered]@{
            ipAddress = $n.IPAddress
            macAddress = $n.LinkLayerAddress
            state = [string]$n.State
        }
    }
}

$neighborMacMultiClaim = @(
    $neighbors |
    Group-Object macAddress |
    Where-Object { (@($_.Group | Select-Object -ExpandProperty ipAddress -Unique)).Count -ge 3 } |
    ForEach-Object {
        [ordered]@{
            macAddress = $_.Name
            ipAddresses = @($_.Group | Select-Object -ExpandProperty ipAddress -Unique)
        }
    }
)
if ($neighborMacMultiClaim.Count -gt 0) {
    $checks.Add((New-Check 'ARP/neighbour anomalies' 'WARN' 'A single MAC is associated with three or more IPv4 addresses. This can be legitimate proxy ARP, but combined with Event 4199 it strongly supports an address-conflict/network-responder problem.' $neighborMacMultiClaim))
}
else {
    $checks.Add((New-Check 'ARP/neighbour anomalies' 'INFO' 'No obvious multi-address MAC pattern in the current neighbour table.'))
}

$winHttpProxy = (& netsh.exe winhttp show proxy 2>&1 | Out-String).Trim()
$internetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$proxyEnable = $false
$proxyServer = $null
$autoConfigUrl = $null
if ($internetSettings) {
    if ($internetSettings.PSObject.Properties['ProxyEnable']) { $proxyEnable = [bool]$internetSettings.ProxyEnable }
    if ($internetSettings.PSObject.Properties['ProxyServer']) { $proxyServer = $internetSettings.ProxyServer }
    if ($internetSettings.PSObject.Properties['AutoConfigURL']) { $autoConfigUrl = $internetSettings.AutoConfigURL }
}
$userProxy = [ordered]@{
    enabled = $proxyEnable
    server = $proxyServer
    autoConfigUrl = $autoConfigUrl
}
$proxyConfigured = ($winHttpProxy -notmatch 'Direct access') -or $userProxy.enabled -or -not [string]::IsNullOrWhiteSpace([string]$userProxy.autoConfigUrl)
$proxyStatus = if ($proxyConfigured) { 'INFO' } else { 'PASS' }
$proxyDetail = if ($proxyConfigured) { 'A WinHTTP or user proxy/PAC setting is present.' } else { 'No explicit WinHTTP or user proxy is configured.' }
$checks.Add((New-Check 'Proxy configuration' $proxyStatus $proxyDetail ([ordered]@{ winHttp = $winHttpProxy; user = $userProxy })))

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsEntries = @()
if (Test-Path $hostsPath) {
    $hostsEntries = @(Get-Content $hostsPath -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') })
}
$hostsStatus = if ($hostsEntries.Count -gt 0) { 'INFO' } else { 'PASS' }
$hostsDetail = if ($hostsEntries.Count -gt 0) { "$($hostsEntries.Count) active hosts-file override(s) found." } else { 'No active hosts-file overrides found.' }
$checks.Add((New-Check 'Hosts file' $hostsStatus $hostsDetail $hostsEntries))

$interestingServices = @()
$servicePattern = '(?i)victory|covenant|tailscale|wireguard|openvpn|pritunl|zerotier|cloudflare|warp|vpn|dns|shield'
foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $servicePattern -or $_.DisplayName -match $servicePattern -or $_.PathName -match $servicePattern })) {
    $interestingServices += [ordered]@{
        name = $svc.Name
        displayName = $svc.DisplayName
        state = $svc.State
        startMode = $svc.StartMode
        processId = $svc.ProcessId
        path = $svc.PathName
    }
}
$checks.Add((New-Check 'VPN/DNS/filter services' 'INFO' "$($interestingServices.Count) potentially network-relevant service(s) detected." $interestingServices))

$otherApipa = @(
    $adapterRecords | Where-Object {
        $_.interfaceIndex -ne $(if ($activeAdapter) { $activeAdapter.ifIndex } else { -1 }) -and
        @($_.ipv4 | Where-Object { $_.address -like '169.254.*' }).Count -gt 0
    }
)
if ($otherApipa.Count -gt 0) {
    $checks.Add((New-Check 'Other APIPA adapters' 'INFO' "$($otherApipa.Count) non-primary adapter(s) have 169.254.x.x addresses. This can matter when a VPN/virtual adapter also influences DNS or routes." $otherApipa))
}

$manualProfiles = @()
foreach ($record in $adapterRecords) {
    if ($record.dhcp -eq 'Disabled' -and $record.ipv4.Count -gt 0) { $manualProfiles += $record }
}
if ($manualProfiles.Count -gt 0) {
    $checks.Add((New-Check 'Manual/static IPv4 profiles' 'INFO' "$($manualProfiles.Count) adapter(s) have DHCP disabled and an IPv4 address. Stale direct-device/NAS profiles can cause DNS or routing confusion when reused." $manualProfiles))
}

$classArgs = @{
    HasConnectedAdapter = $connected
    HasApipa = $hasApipa
    HasDuplicateAddress = $hasDuplicateAddress
    HasGateway = $hasGateway
    InternetPing = $internetPing
    CurrentDns = [bool]$currentDns.success
    DirectDns = $directDns
    Https = [bool]$httpsAny.success
}
$classification = Get-Classification @classArgs

$timestamp = Get-Date
$runFolder = Join-Path $OutputDirectory ("Network-{0}" -f $timestamp.ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null

$activeRecord = $null
if ($activeAdapter) {
    $activeRecord = [ordered]@{
        name = $activeAdapter.Name
        description = $activeAdapter.InterfaceDescription
        interfaceIndex = $activeAdapter.ifIndex
        macAddress = $activeAdapter.MacAddress
        status = [string]$activeAdapter.Status
        linkSpeed = [string]$activeAdapter.LinkSpeed
        dhcp = if ($activeInterface) { [string]$activeInterface.Dhcp } else { $null }
        ipv4 = @($activeAddresses | ForEach-Object IPAddress)
        gateway = $gateway
        dnsServers = $dnsServers
    }
}

$report = [ordered]@{
    schemaVersion = 1
    generatedAt = $timestamp.ToString('o')
    computerName = $env:COMPUTERNAME
    mode = 'Diagnose'
    classification = $classification.classification
    severity = $classification.severity
    summary = $classification.summary
    nextAction = $classification.nextAction
    activeAdapter = $activeRecord
    checks = $checks
    duplicateAddressConflicts = $duplicateEvents
    neighbors = $neighbors
    adapters = $adapterRecords
    dns = [ordered]@{
        configuredServers = $dnsServers
        currentResolver = $currentDns
        directCloudflare = $directDns1
        directGoogle = $directDns8
        loopbackListeners = $dnsListeners
    }
    connectivity = [ordered]@{
        gatewayPing = $gatewayPing
        publicIpPing = $internetPing
        tcp443Github = $tcp443
        https = $httpsAny
        httpsIpv4 = $https4
        httpsIpv6 = $https6
    }
    proxy = [ordered]@{
        winHttp = $winHttpProxy
        user = $userProxy
    }
    networkRelevantServices = $interestingServices
}

$jsonPath = Join-Path $runFolder 'network-doctor-report.json'
$mdPath = Join-Path $runFolder 'network-doctor-report.md'
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Windows Crash Doctor - Network Doctor report')
$md.Add('')
$md.Add("Generated: **$($report.generatedAt)**")
$md.Add("Computer: **$($report.computerName)**")
$md.Add('')
$md.Add('## Diagnosis')
$md.Add('')
$md.Add("**$($report.classification)**")
$md.Add('')
$md.Add($report.summary)
$md.Add('')
$md.Add("**Next action:** $($report.nextAction)")
$md.Add('')
$md.Add('## Checks')
$md.Add('')
foreach ($check in $checks) {
    $md.Add("- **[$($check.status)] $($check.name):** $($check.detail)")
}
if ($duplicateEvents.Count -gt 0) {
    $md.Add('')
    $md.Add('## Recent duplicate-address conflicts')
    $md.Add('')
    foreach ($evt in $duplicateEvents | Select-Object -First 15) {
        $md.Add("- $($evt.timeCreated): IP $($evt.ipAddress) from MAC $($evt.macAddress)")
    }
}
$md.Add('')
$md.Add('## Safety boundary')
$md.Add('')
$md.Add('Network Doctor diagnoses by default. It does not silently change DNS servers, force DHCP, reset Winsock/TCP-IP, disable security software, alter VPNs, or assign a static IP.')
$md | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Output "CLASSIFICATION: $($report.classification)"
Write-Output "SUMMARY: $($report.summary)"
Write-Output "NEXT: $($report.nextAction)"
Write-Output "REPORT_JSON: $jsonPath"
Write-Output "REPORT_MD: $mdPath"
