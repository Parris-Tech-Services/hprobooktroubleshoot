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

    try {
        return [bool](Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Test-DnsTarget {
    param(
        [string]$Name = 'google.com',
        [string]$Server
    )

    try {
        $params = @{
            Name = $Name
            Type = 'A'
            DnsOnly = $true
            QuickTimeout = $true
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $params.Server = $Server
        }

        $result = Resolve-DnsName @params |
            Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress } |
            Select-Object -First 1

        return [ordered]@{
            success = [bool]$result
            address = if ($result) { [string]$result.IPAddress } else { $null }
            error = $null
        }
    }
    catch {
        return [ordered]@{
            success = $false
            address = $null
            error = $_.Exception.Message
        }
    }
}

function Test-HttpsTarget {
    param(
        [string]$Url = 'https://www.google.com',
        [ValidateSet('Any','IPv4','IPv6')]
        [string]$Family = 'Any'
    )

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        try {
            $args = @('-sS','-I','--max-time','8','-o','NUL','-w','%{http_code}')
            if ($Family -eq 'IPv4') { $args += '-4' }
            if ($Family -eq 'IPv6') { $args += '-6' }
            $args += $Url

            $output = & $curl.Source @args 2>&1
            $exitCode = $LASTEXITCODE
            $text = ($output | Out-String).Trim()
            $match = [regex]::Match($text, '(?<code>\d{3})\s*$')
            $code = $null
            if ($match.Success) {
                $code = [int]$match.Groups['code'].Value
            }

            return [ordered]@{
                success = ($exitCode -eq 0 -and $null -ne $code -and $code -ge 200 -and $code -lt 500)
                statusCode = $code
                error = if ($exitCode -eq 0) { $null } else { $text }
            }
        }
        catch {
            return [ordered]@{
                success = $false
                statusCode = $null
                error = $_.Exception.Message
            }
        }
    }

    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = 'HEAD'
        $request.Timeout = 8000
        $response = $request.GetResponse()
        $code = [int]$response.StatusCode
        $response.Close()

        return [ordered]@{
            success = ($code -ge 200 -and $code -lt 500)
            statusCode = $code
            error = $null
        }
    }
    catch {
        return [ordered]@{
            success = $false
            statusCode = $null
            error = $_.Exception.Message
        }
    }
}

function Get-Classification {
    param(
        [bool]$HasConnectedAdapter,
        [bool]$HasRecentWifiAuthFailure,
        [bool]$HasApipa,
        [bool]$HasDuplicateAddress,
        [bool]$HasGateway,
        [bool]$InternetReachable,
        [bool]$CurrentDns,
        [bool]$DirectDns,
        [bool]$Https
    )

    if ($HasDuplicateAddress) {
        return [ordered]@{
            classification = 'Duplicate IP address conflict'
            severity = 'High'
            summary = 'Windows has evidence that another device or network component is answering for an address assigned to this PC.'
            nextAction = 'Identify the conflicting MAC/device from Event 4199 and neighbour evidence. Do not hide the fault with a random static IP.'
        }
    }

    if (-not $HasConnectedAdapter -and $HasRecentWifiAuthFailure) {
        return [ordered]@{
            classification = 'Wi-Fi authentication failure'
            severity = 'High'
            summary = 'Recent WLAN AutoConfig evidence points to Wi-Fi security/authentication failure rather than DHCP, DNS or internet routing.'
            nextAction = 'Verify the intended SSID and re-enter the known-correct Wi-Fi password or required 802.1X credentials before resetting drivers or the TCP/IP stack.'
        }
    }

    if (-not $HasConnectedAdapter) {
        return [ordered]@{
            classification = 'No connected network adapter'
            severity = 'High'
            summary = 'Windows cannot see a connected Ethernet or Wi-Fi path.'
            nextAction = 'Check Ethernet link state or Wi-Fi association first. Do not start with DNS changes.'
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
            summary = 'The active adapter has no usable IPv4 or IPv6 default gateway.'
            nextAction = 'Check DHCP/static configuration and compare the gateway with a working device on the same network.'
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

    if (-not $CurrentDns -and -not $DirectDns -and $InternetReachable) {
        return [ordered]@{
            classification = 'DNS path failure'
            severity = 'High'
            summary = 'Raw IP connectivity works but DNS resolution is failing through both the configured resolver and direct public resolvers.'
            nextAction = 'Check DNS interception, firewall/security policy, VPN/filter software and upstream DNS reachability.'
        }
    }

    if (-not $InternetReachable -and -not $Https) {
        return [ordered]@{
            classification = 'Upstream connectivity failure'
            severity = 'High'
            summary = 'The PC has local addressing but cannot reach a public IP or complete an HTTPS request.'
            nextAction = 'Check gateway reachability, router/ISP state, VLAN/firewall path and whether other devices on the same network are affected.'
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

    return [ordered]@{
        classification = 'Windows network path healthy'
        severity = 'None'
        summary = 'Addressing, DNS and HTTPS tests passed from Windows.'
        nextAction = 'If an app or browser still fails, focus on the browser/app layer: profile/session, extension, QUIC, TLS inspection, local security integration or app-specific proxy behaviour.'
    }
}

function Invoke-SelfTest {
    $cases = @(
        @{
            name = 'duplicate'
            values = @($true,$false,$false,$true,$true,$true,$true,$true,$true)
            expected = 'Duplicate IP address conflict'
        },
        @{
            name = 'wifi-auth'
            values = @($false,$true,$false,$false,$false,$false,$false,$false,$false)
            expected = 'Wi-Fi authentication failure'
        },
        @{
            name = 'apipa'
            values = @($true,$false,$true,$false,$false,$false,$false,$false,$false)
            expected = 'DHCP/addressing failure'
        },
        @{
            name = 'dns'
            values = @($true,$false,$false,$false,$true,$true,$false,$true,$true)
            expected = 'DNS resolver/filter failure'
        },
        @{
            name = 'dns-with-ping-blocked'
            values = @($true,$false,$false,$false,$true,$false,$false,$true,$false)
            expected = 'DNS resolver/filter failure'
        },
        @{
            name = 'https'
            values = @($true,$false,$false,$false,$true,$true,$true,$true,$false)
            expected = 'HTTPS/TLS/filtering failure'
        },
        @{
            name = 'healthy'
            values = @($true,$false,$false,$false,$true,$true,$true,$true,$true)
            expected = 'Windows network path healthy'
        }
    )

    foreach ($case in $cases) {
        $v = $case.values
        $selfArgs = @{
            HasConnectedAdapter = $v[0]
            HasRecentWifiAuthFailure = $v[1]
            HasApipa = $v[2]
            HasDuplicateAddress = $v[3]
            HasGateway = $v[4]
            InternetReachable = $v[5]
            CurrentDns = $v[6]
            DirectDns = $v[7]
            Https = $v[8]
        }
        $result = Get-Classification @selfArgs

        if ($result.classification -ne $case.expected) {
            throw "Network Doctor self-test '$($case.name)' failed: expected '$($case.expected)', got '$($result.classification)'."
        }
    }

    Write-Output 'Network Doctor self-test passed.'
}

if ($SelfTest) {
    Invoke-SelfTest
    exit 0
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$defaultRoute4 = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

$defaultRoute6 = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

$defaultRoute = $null
if ($defaultRoute4) {
    $defaultRoute = $defaultRoute4
}
elseif ($defaultRoute6) {
    $defaultRoute = $defaultRoute6
}

$activeAdapter = $null
if ($defaultRoute) {
    $activeAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
}
if (-not $activeAdapter) {
    $activeAdapter = Get-NetAdapter -Name '*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } |
        Sort-Object ifIndex |
        Select-Object -First 1
}

if ($Mode -eq 'Refresh') {
    if (-not $activeAdapter) {
        throw 'No connected adapter was found to refresh.'
    }

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

foreach ($adapter in @(Get-NetAdapter -Name '*' -ErrorAction SilentlyContinue)) {
    $ipv4 = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' })
    $ipv6 = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne '::1' })

    $iface4 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue

    $adapterRecords += [ordered]@{
        name = $adapter.Name
        description = $adapter.InterfaceDescription
        status = [string]$adapter.Status
        macAddress = $adapter.MacAddress
        linkSpeed = [string]$adapter.LinkSpeed
        interfaceIndex = [int]$adapter.ifIndex
        hardwareInterface = [bool]$adapter.HardwareInterface
        dhcp = if ($iface4) { [string]$iface4.Dhcp } else { $null }
        ipv4 = @($ipv4 | ForEach-Object {
            [ordered]@{
                address = $_.IPAddress
                prefixLength = $_.PrefixLength
                addressState = [string]$_.AddressState
                prefixOrigin = [string]$_.PrefixOrigin
                suffixOrigin = [string]$_.SuffixOrigin
            }
        })
        ipv6 = @($ipv6 | ForEach-Object {
            [ordered]@{
                address = $_.IPAddress
                prefixLength = $_.PrefixLength
                addressState = [string]$_.AddressState
            }
        })
    }
}

$connected = [bool]$activeAdapter
$activeConfig = $null
$activeInterface4 = $null
$activeAddresses4 = @()
$activeAddresses6 = @()

if ($activeAdapter) {
    $activeConfig = Get-NetIPConfiguration -InterfaceIndex $activeAdapter.ifIndex -ErrorAction SilentlyContinue
    $activeInterface4 = Get-NetIPInterface -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $activeAddresses4 = @(Get-NetIPAddress -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' })
    $activeAddresses6 = @(Get-NetIPAddress -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne '::1' -and $_.IPAddress -notlike 'fe80:*' })
}

$hasApipa = [bool]($activeAddresses4 | Where-Object { $_.IPAddress -like '169.254.*' })
$hasDuplicateAddress = [bool]($activeAddresses4 | Where-Object { [string]$_.AddressState -eq 'Duplicate' })

$gateway4 = $null
$gateway6 = $null
if ($activeConfig) {
    if ($activeConfig.IPv4DefaultGateway) {
        $gateway4 = [string]$activeConfig.IPv4DefaultGateway.NextHop
    }
    if ($activeConfig.IPv6DefaultGateway) {
        $gateway6 = [string]$activeConfig.IPv6DefaultGateway.NextHop
    }
}

$gateway = $null
if (-not [string]::IsNullOrWhiteSpace($gateway4)) {
    $gateway = $gateway4
}
elseif (-not [string]::IsNullOrWhiteSpace($gateway6)) {
    $gateway = $gateway6
}
$hasGateway = -not [string]::IsNullOrWhiteSpace($gateway)

if ($connected) {
    $checks.Add((New-Check 'Connected adapter' 'PASS' "$($activeAdapter.Name) - $($activeAdapter.InterfaceDescription) - $($activeAdapter.LinkSpeed)"))
}
else {
    $checks.Add((New-Check 'Connected adapter' 'FAIL' 'No connected physical adapter was found.'))
}

if ($activeAdapter) {
    $ipStatus = 'FAIL'
    $ipDetail = 'No usable IPv4 or global IPv6 address found.'

    if ($hasApipa) {
        $ipStatus = 'FAIL'
        $ipDetail = 'APIPA 169.254.x.x detected.'
    }
    elseif ($activeAddresses4.Count -gt 0) {
        $ipStatus = 'PASS'
        $addresses = ($activeAddresses4 | ForEach-Object { $_.IPAddress }) -join ', '
        $dhcpText = if ($activeInterface4) { [string]$activeInterface4.Dhcp } else { 'Unknown' }
        $ipDetail = "$addresses | DHCP $dhcpText"
    }
    elseif ($activeAddresses6.Count -gt 0) {
        $ipStatus = 'INFO'
        $ipDetail = 'No usable IPv4 address, but a global IPv6 address is present.'
    }

    $checks.Add((New-Check 'IP configuration' $ipStatus $ipDetail))
}

$gatewayPing = $false
if ($hasGateway) {
    $gatewayPing = Test-PingTarget $gateway
    $gatewayStatus = if ($gatewayPing) { 'PASS' } else { 'WARN' }
    $gatewayDetail = if ($gatewayPing) { "$gateway | ping passed" } else { "$gateway | ping did not reply" }
    $checks.Add((New-Check 'Default gateway' $gatewayStatus $gatewayDetail))
}
else {
    $checks.Add((New-Check 'Default gateway' 'FAIL' 'No IPv4 or IPv6 default gateway is configured.'))
}

$dhcpService = Get-Service Dhcp -ErrorAction SilentlyContinue
if ($dhcpService) {
    $dhcpStatus = if ($dhcpService.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
    $checks.Add((New-Check 'DHCP Client service' $dhcpStatus "Status: $($dhcpService.Status)"))
}

$internetPing4 = Test-PingTarget '8.8.8.8'
$internetPing6 = Test-PingTarget '2001:4860:4860::8888'
$internetReachable = [bool]($internetPing4 -or $internetPing6)
$internetStatus = if ($internetReachable) { 'PASS' } else { 'WARN' }
$checks.Add((New-Check 'Public IP reachability' $internetStatus "IPv4 ping: $internetPing4; IPv6 ping: $internetPing6"))

$dnsServers4 = @()
$dnsServers6 = @()
if ($activeAdapter) {
    $dns4 = Get-DnsClientServerAddress -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $dns6 = Get-DnsClientServerAddress -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
    if ($dns4) { $dnsServers4 = @($dns4.ServerAddresses) }
    if ($dns6) { $dnsServers6 = @($dns6.ServerAddresses) }
}
$dnsServers = @($dnsServers4 + $dnsServers6 | Where-Object { $_ } | Select-Object -Unique)

$currentDns = Test-DnsTarget
$currentDnsStatus = if ($currentDns.success) { 'PASS' } else { 'FAIL' }
$currentDnsDetail = if ($currentDns.success) { "google.com -> $($currentDns.address)" } else { "Failed: $($currentDns.error)" }
$checks.Add((New-Check 'Configured DNS resolution' $currentDnsStatus $currentDnsDetail $dnsServers))

$directDns1 = Test-DnsTarget -Server '1.1.1.1'
$directDns8 = Test-DnsTarget -Server '8.8.8.8'
$directDns1v6 = Test-DnsTarget -Server '2606:4700:4700::1111'
$directDns8v6 = Test-DnsTarget -Server '2001:4860:4860::8888'
$directDns = [bool]($directDns1.success -or $directDns8.success -or $directDns1v6.success -or $directDns8v6.success)
$directDnsStatus = if ($directDns) { 'PASS' } else { 'WARN' }
$directDnsDetail = "Cloudflare v4: $($directDns1.success); Google v4: $($directDns8.success); Cloudflare v6: $($directDns1v6.success); Google v6: $($directDns8v6.success)"
$checks.Add((New-Check 'Direct public DNS' $directDnsStatus $directDnsDetail))

$loopbackDns = @($dnsServers | Where-Object { $_ -eq '::1' -or $_ -like '127.*' })
$dnsListeners = @()
if ($loopbackDns.Count -gt 0) {
    $allServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
    $listenerPids = @()

    foreach ($endpoint in @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)) {
        $listenerPids += $endpoint.OwningProcess
    }
    foreach ($endpoint in @(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue)) {
        $listenerPids += $endpoint.OwningProcess
    }

    foreach ($pid in @($listenerPids | Sort-Object -Unique)) {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        $svc = $allServices | Where-Object { $_.ProcessId -eq $pid } | Select-Object -First 1

        $dnsListeners += [ordered]@{
            pid = $pid
            process = if ($proc) { $proc.ProcessName } else { $null }
            service = if ($svc) { $svc.Name } else { $null }
            serviceDisplayName = if ($svc) { $svc.DisplayName } else { $null }
            servicePath = if ($svc) { $svc.PathName } else { $null }
        }
    }

    $listenerNames = @()
    foreach ($listener in $dnsListeners) {
        if ($listener.serviceDisplayName) {
            $listenerNames += $listener.serviceDisplayName
        }
        elseif ($listener.process) {
            $listenerNames += $listener.process
        }
    }

    $loopStatus = if ($currentDns.success) { 'INFO' } else { 'FAIL' }
    if ($listenerNames.Count -gt 0) {
        $loopDetail = 'Loopback DNS is configured. Listener: ' + ($listenerNames -join ', ')
    }
    else {
        $loopDetail = 'Loopback DNS is configured but no port-53 owner was identified.'
    }

    $checks.Add((New-Check 'Local DNS/filter service' $loopStatus $loopDetail $dnsListeners))
}

$httpsAny = Test-HttpsTarget
$https4 = Test-HttpsTarget -Family IPv4
$https6 = Test-HttpsTarget -Family IPv6

$httpsStatus = if ($httpsAny.success) { 'PASS' } else { 'FAIL' }
$https4Status = if ($https4.success) { 'PASS' } else { 'WARN' }
$checks.Add((New-Check 'HTTPS' $httpsStatus "google.com HTTPS status: $($httpsAny.statusCode)"))
$checks.Add((New-Check 'HTTPS IPv4' $https4Status "IPv4 HTTPS success: $($https4.success); status: $($https4.statusCode)"))
$checks.Add((New-Check 'HTTPS IPv6' 'INFO' "IPv6 HTTPS success: $($https6.success); status: $($https6.statusCode)"))

$tcp443 = $false
try {
    $tcp443 = [bool](Test-NetConnection -ComputerName 'github.com' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
}
catch {
    $tcp443 = $false
}
$tcp443Status = if ($tcp443) { 'PASS' } else { 'WARN' }
$checks.Add((New-Check 'TCP 443' $tcp443Status "github.com:443 reachable: $tcp443"))

$duplicateEvents = @()
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id = 4199
        StartTime = (Get-Date).AddDays(-30)
    } -ErrorAction Stop | Select-Object -First 50

    foreach ($evt in @($events)) {
        $ip = $null
        $mac = $null
        $match = [regex]::Match(
            $evt.Message,
            '(?i)IP address\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3}).*?hardware address\s+(?<mac>[0-9A-F-]{11,})'
        )
        if ($match.Success) {
            $ip = $match.Groups['ip'].Value
            $mac = $match.Groups['mac'].Value.ToUpperInvariant()
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
    $recentCutoff = (Get-Date).AddMinutes(-30)
    $recentDuplicate = @($duplicateEvents | Where-Object { [datetime]$_.timeCreated -ge $recentCutoff })

    $multiClaimMac = @(
        $duplicateEvents |
            Where-Object { $_.macAddress } |
            Group-Object macAddress |
            Where-Object {
                (@($_.Group | Select-Object -ExpandProperty ipAddress -Unique)).Count -ge 2
            } |
            ForEach-Object { $_.Name }
    )

    if ($recentDuplicate.Count -gt 0) {
        $hasDuplicateAddress = $true
    }

    $detail = "$($duplicateEvents.Count) conflict event(s) in 30 days"
    if ($multiClaimMac.Count -gt 0) {
        $detail += '; MAC(s) seen claiming multiple IPs: ' + ($multiClaimMac -join ', ')
    }

    $dupStatus = if ($recentDuplicate.Count -gt 0) { 'FAIL' } else { 'WARN' }
    $checks.Add((New-Check 'Duplicate-IP history' $dupStatus $detail $duplicateEvents))
}
else {
    $checks.Add((New-Check 'Duplicate-IP history' 'PASS' 'No Event 4199 address-conflict records found in the last 30 days.'))
}

$neighbors = @()
if ($activeAdapter) {
    foreach ($neighbor in @(Get-NetNeighbor -InterfaceIndex $activeAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($neighbor.LinkLayerAddress -and $neighbor.LinkLayerAddress -ne '00-00-00-00-00-00') {
            $neighbors += [ordered]@{
                ipAddress = $neighbor.IPAddress
                macAddress = $neighbor.LinkLayerAddress
                state = [string]$neighbor.State
            }
        }
    }
}

$neighborMacMultiClaim = @(
    $neighbors |
        Group-Object macAddress |
        Where-Object {
            (@($_.Group | Select-Object -ExpandProperty ipAddress -Unique)).Count -ge 3
        } |
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

$winHttpProxy = ''
try {
    $winHttpProxy = (& netsh.exe winhttp show proxy 2>&1 | Out-String).Trim()
}
catch { }

$internetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$proxyEnable = $false
$proxyServer = $null
$autoConfigUrl = $null

if ($internetSettings) {
    if ($internetSettings.PSObject.Properties['ProxyEnable']) {
        $proxyEnable = [bool]$internetSettings.ProxyEnable
    }
    if ($internetSettings.PSObject.Properties['ProxyServer']) {
        $proxyServer = $internetSettings.ProxyServer
    }
    if ($internetSettings.PSObject.Properties['AutoConfigURL']) {
        $autoConfigUrl = $internetSettings.AutoConfigURL
    }
}

$userProxy = [ordered]@{
    enabled = $proxyEnable
    server = $proxyServer
    autoConfigUrl = $autoConfigUrl
}

$proxyConfigured = ($winHttpProxy -notmatch 'Direct access') -or
    $userProxy.enabled -or
    (-not [string]::IsNullOrWhiteSpace([string]$userProxy.autoConfigUrl))

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
    Where-Object {
        $_.Name -match $servicePattern -or
        $_.DisplayName -match $servicePattern -or
        $_.PathName -match $servicePattern
    })) {

    $interestingServices += [ordered]@{
        name = $svc.Name
        displayName = $svc.DisplayName
        state = $svc.State
        startMode = $svc.StartMode
        processId = $svc.ProcessId
        path = $svc.PathName
    }
}
$checks.Add((New-Check 'VPN/DNS/filter services' 'INFO' "$($interestingServices.Count) potentially network-relevant service(s) detected. These are inventoried, not disabled." $interestingServices))

$activeIndex = -1
if ($activeAdapter) {
    $activeIndex = $activeAdapter.ifIndex
}

$otherApipa = @(
    $adapterRecords | Where-Object {
        $_.interfaceIndex -ne $activeIndex -and
        @($_.ipv4 | Where-Object { $_.address -like '169.254.*' }).Count -gt 0
    }
)
if ($otherApipa.Count -gt 0) {
    $checks.Add((New-Check 'Other APIPA adapters' 'INFO' "$($otherApipa.Count) non-primary adapter(s) have 169.254.x.x addresses. This can matter when a VPN or virtual adapter also influences DNS or routes." $otherApipa))
}

$manualProfiles = @()
foreach ($record in $adapterRecords) {
    if ($record.dhcp -eq 'Disabled' -and $record.ipv4.Count -gt 0) {
        $manualProfiles += $record
    }
}
if ($manualProfiles.Count -gt 0) {
    $checks.Add((New-Check 'Manual/static IPv4 profiles' 'INFO' "$($manualProfiles.Count) adapter(s) have DHCP disabled and an IPv4 address. Stale direct-device or NAS profiles can cause routing/DNS confusion when reused." $manualProfiles))
}

$wifiAdapters = @(
    $adapterRecords |
        Where-Object { $_.description -match '(?i)wi-?fi|wireless|802\.11' }
)

$wlanInterfacesText = ''
$wlanProfilesText = ''
$wlanNetworksText = ''
$wlanDriversText = ''

try { $wlanInterfacesText = (& netsh.exe wlan show interfaces 2>&1 | Out-String).Trim() } catch { }
try { $wlanProfilesText = (& netsh.exe wlan show profiles 2>&1 | Out-String).Trim() } catch { }
try { $wlanNetworksText = (& netsh.exe wlan show networks mode=bssid 2>&1 | Out-String).Trim() } catch { }
try { $wlanDriversText = (& netsh.exe wlan show drivers 2>&1 | Out-String).Trim() } catch { }

$wlanEvents = @()
$wlanLog = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $wlanLog
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction Stop | Select-Object -First 80

    foreach ($evt in @($events)) {
        $wlanEvents += [ordered]@{
            timeCreated = $evt.TimeCreated.ToString('o')
            id = $evt.Id
            level = $evt.LevelDisplayName
            message = $evt.Message
        }
    }
}
catch { }

$authEvidence = @(
    $wlanEvents |
        Where-Object {
            $_.message -match '(?i)pre-shared key|PSK|password|passphrase|authentication|802\.1x|certificate|cancelled'
        }
)

$pskMismatch = @(
    $wlanEvents |
        Where-Object {
            $_.message -match '(?i)PSK.*mismatch|pre-shared key.*(incorrect|mismatch)|incorrect.*(password|passphrase|key)'
        }
)

$recentWifiCutoff = (Get-Date).AddHours(-1)
$recentWifiAuthFailures = @(
    $authEvidence |
        Where-Object { [datetime]$_.timeCreated -ge $recentWifiCutoff }
)
$hasRecentWifiAuthFailure = ($recentWifiAuthFailures.Count -gt 0)

if ($wifiAdapters.Count -gt 0) {
    if ($pskMismatch.Count -gt 0) {
        $checks.Add((New-Check 'Wi-Fi authentication history' 'WARN' 'WLAN AutoConfig history contains evidence consistent with an incorrect Wi-Fi pre-shared key/passphrase. Re-enter the known-correct password before resetting the TCP/IP stack or reinstalling drivers.' $pskMismatch))
    }
    elseif ($authEvidence.Count -gt 0) {
        $checks.Add((New-Check 'Wi-Fi authentication history' 'INFO' "$($authEvidence.Count) recent WLAN authentication/profile event(s) found. Preserve event IDs and timestamps before changing the profile or driver." $authEvidence))
    }
    else {
        $checks.Add((New-Check 'Wi-Fi authentication history' 'INFO' 'No obvious recent PSK/passphrase/authentication failure was identified in WLAN AutoConfig history.'))
    }
}

$connectivityProbe = [ordered]@{
    success = $false
    statusCode = $null
    body = $null
    error = $null
}
try {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $writeOut = [Environment]::NewLine + '%{http_code}'
        $probeOutput = & $curl.Source -sS -L --max-time 8 -w $writeOut 'http://www.msftconnecttest.com/connecttest.txt' 2>&1
        $probeText = ($probeOutput | Out-String).Trim()
        $parts = @($probeText -split '\r?\n')

        if ($parts.Count -gt 0) {
            $last = $parts[$parts.Count - 1]
            if ($last -match '^\d{3}$') {
                $connectivityProbe.statusCode = [int]$last
            }
        }

        if ($parts.Count -gt 1) {
            $bodyLines = $parts[0..($parts.Count - 2)]
            $connectivityProbe.body = ($bodyLines -join [Environment]::NewLine).Trim()
        }
        else {
            $connectivityProbe.body = ''
        }

        $connectivityProbe.success =
            ($connectivityProbe.statusCode -eq 200 -and
             $connectivityProbe.body -match 'Microsoft Connect Test')
    }
}
catch {
    $connectivityProbe.error = $_.Exception.Message
}

if ($connectivityProbe.success) {
    $checks.Add((New-Check 'Captive portal / connectivity probe' 'PASS' 'Windows-style internet connectivity probe reached the expected public response.'))
}
elseif ($httpsAny.success) {
    $checks.Add((New-Check 'Captive portal / connectivity probe' 'INFO' 'HTTPS works, but the Microsoft connectivity probe did not return the expected body. Filtering or captive-portal interception may be involved.' $connectivityProbe))
}

$winsockCatalog = ''
try {
    $winsockCatalog = (& netsh.exe winsock show catalog 2>&1 | Out-String)
}
catch { }

$winsockProviders = @()
if ($winsockCatalog) {
    $matches = [regex]::Matches(
        $winsockCatalog,
        '(?im)^\s*(?:Catalog Entry|Protocol|Provider Path|Description).*?$'
    )

    $winsockProviders = @(
        $matches |
            ForEach-Object { $_.Value.Trim() } |
            Select-Object -First 120
    )
}
$checks.Add((New-Check 'Winsock/LSP inventory' 'INFO' 'Captured Winsock provider metadata for comparison. Network Doctor does not automatically reset Winsock because that is a broad remediation step.' $winsockProviders))

$timeSyncText = ''
try {
    $timeSyncText = (& w32tm.exe /query /status 2>&1 | Out-String).Trim()
}
catch { }

$clockStatus = 'INFO'
$clockDetail = 'Captured Windows Time status for TLS/certificate troubleshooting.'
if ($timeSyncText -match '(?i)The service has not been started|error|unsynchronized|free-running') {
    $clockStatus = 'WARN'
    $clockDetail = 'Windows Time reports a possible synchronisation problem. A materially wrong clock can break TLS/certificate validation.'
}
$checks.Add((New-Check 'System time synchronisation' $clockStatus $clockDetail $timeSyncText))

$defaultRoutes = @()
$defaultRoutes += @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
$defaultRoutes += @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
$defaultRoutes = @(
    $defaultRoutes |
        Sort-Object AddressFamily, RouteMetric, InterfaceMetric |
        Select-Object AddressFamily, InterfaceIndex, NextHop, RouteMetric, InterfaceMetric, State, PolicyStore
)

if ($defaultRoutes.Count -gt 2) {
    $checks.Add((New-Check 'Competing default routes' 'INFO' "$($defaultRoutes.Count) IPv4/IPv6 default routes are present. VPNs and virtual adapters can legitimately add routes, but metrics should be reviewed if traffic takes the wrong path." $defaultRoutes))
}
else {
    $checks.Add((New-Check 'Default-route inventory' 'INFO' "$($defaultRoutes.Count) default route(s) captured." $defaultRoutes))
}

$browserProcesses = @(
    Get-Process chrome,msedge,firefox -ErrorAction SilentlyContinue |
        Select-Object ProcessName,Id,Path
)
if ($httpsAny.success -and $currentDns.success) {
    $checks.Add((New-Check 'Browser-vs-network boundary' 'INFO' 'Windows DNS and HTTPS tests passed. If a browser still cannot load pages, the failure is likely above the basic network path: browser profile/session, extension, QUIC, TLS inspection, security integration or app-specific proxy behaviour.' $browserProcesses))
}

$classArgs = @{
    HasConnectedAdapter = $connected
    HasRecentWifiAuthFailure = $hasRecentWifiAuthFailure
    HasApipa = $hasApipa
    HasDuplicateAddress = $hasDuplicateAddress
    HasGateway = $hasGateway
    InternetReachable = $internetReachable
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
        dhcp = if ($activeInterface4) { [string]$activeInterface4.Dhcp } else { $null }
        ipv4 = @($activeAddresses4 | ForEach-Object { $_.IPAddress })
        ipv6 = @($activeAddresses6 | ForEach-Object { $_.IPAddress })
        gateway = $gateway
        gatewayIpv4 = $gateway4
        gatewayIpv6 = $gateway6
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
        directCloudflareIpv4 = $directDns1
        directGoogleIpv4 = $directDns8
        directCloudflareIpv6 = $directDns1v6
        directGoogleIpv6 = $directDns8v6
        loopbackListeners = $dnsListeners
    }
    connectivity = [ordered]@{
        gatewayPing = $gatewayPing
        publicIpReachable = $internetReachable
        publicIpv4Ping = $internetPing4
        publicIpv6Ping = $internetPing6
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
    wifi = [ordered]@{
        interfaces = $wlanInterfacesText
        profiles = $wlanProfilesText
        visibleNetworks = $wlanNetworksText
        drivers = $wlanDriversText
        recentEvents = $wlanEvents
    }
    connectivityProbe = $connectivityProbe
    winsockProviders = $winsockProviders
    timeSync = $timeSyncText
    defaultRoutes = $defaultRoutes
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
$md.Add('Network Doctor diagnoses by default. It does not silently change DNS servers, force DHCP, reset Winsock/TCP-IP, disable security software, alter VPNs, reveal Wi-Fi passwords or assign a static IP.')

$md | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Output "CLASSIFICATION: $($report.classification)"
Write-Output "SUMMARY: $($report.summary)"
Write-Output "NEXT: $($report.nextAction)"
Write-Output "REPORT_JSON: $jsonPath"
Write-Output "REPORT_MD: $mdPath"
