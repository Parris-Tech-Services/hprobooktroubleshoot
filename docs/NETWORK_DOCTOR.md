# Network Doctor

Network Doctor is the network-triage workspace inside **Windows Crash Doctor**. It exists so common Windows internet failures can be diagnosed automatically instead of requiring a long sequence of one-off PowerShell commands.

## Design goal

Work from the bottom of the stack upward and keep evidence separate from remediation:

1. adapter and link;
2. IPv4/DHCP state;
3. routes and gateway;
4. duplicate-address evidence;
5. DNS;
6. public IP reachability;
7. TCP 443 and HTTPS;
8. IPv4 versus IPv6;
9. proxy/captive-portal state;
10. Wi-Fi association/authentication history;
11. VPN, DNS-filter and security-service interactions;
12. browser/app-only failures.

A failed ping alone is **not** treated as proof that the internet is down.

## What the current implementation collects

- active and non-primary network adapters;
- MAC address, link speed, DHCP state and IPv4 addresses;
- APIPA / `169.254.x.x` detection;
- default gateway and gateway reachability;
- DHCP Client service state;
- public-IP reachability;
- configured DNS versus direct Cloudflare/Google DNS;
- loopback DNS listeners and the process/service that owns UDP 53;
- HTTPS over the default stack, IPv4 and IPv6;
- TCP 443 reachability;
- System Event **4199** duplicate-address history;
- neighbour/ARP patterns, including one MAC answering for multiple IPv4 addresses;
- WinHTTP and per-user proxy/PAC state;
- active hosts-file overrides;
- potentially relevant VPN/DNS/filter services;
- stale/manual IPv4 profiles on other adapters;
- recent WLAN AutoConfig events;
- Wi-Fi authentication/passphrase evidence;
- a Microsoft-style connectivity/captive-portal probe;
- Winsock provider inventory;
- browser-versus-Windows network boundary evidence.

The report is written as both JSON and Markdown under **Windows Crash Doctor Results**.

## Lessons encoded from real troubleshooting

### Repeated duplicate-IP / mesh behaviour

A Windows PC can receive a valid DHCP lease and then reject it as **Duplicate**, fall back to APIPA, and appear to have a DHCP problem. Event 4199 plus the neighbour table can show that the same MAC is answering for multiple addresses. Network Doctor therefore checks duplicate-address evidence before recommending DNS changes or a static IP.

### Local DNS filtering

A loopback DNS server such as `127.0.0.2` may be intentional security/filtering software rather than a broken Windows setting. Network Doctor identifies the process/service listening on port 53 and compares the configured resolver with direct public DNS. It does **not** silently remove or bypass filtering software.

### Wi-Fi password versus driver failure

A laptop may work on one Wi-Fi network while repeatedly failing on another. Driver reinstall, Winsock reset and TCP/IP reset are not good first-line answers when WLAN AutoConfig evidence points to authentication. Network Doctor preserves recent WLAN event IDs/timestamps and looks for PSK/passphrase mismatch evidence before suggesting broad stack resets.

### Browser-only failures

If raw IP reachability, DNS and HTTPS all succeed from Windows while Chrome/Edge/Firefox still cannot load pages, Network Doctor classifies the basic network path as healthy and shifts attention to the browser/app layer: profile/session, extension, QUIC, TLS inspection, local security integration or app-specific proxy behaviour.

## Safety boundary

Diagnosis is read-only by default.

The app does **not** silently:

- force public DNS servers;
- remove a DNS filter or accountability product;
- disable VPN/security software;
- reset Winsock/TCP-IP;
- delete Wi-Fi profiles;
- reveal saved Wi-Fi passwords;
- assign a static IP;
- disable IPv6;
- restart routers or mesh nodes.

The **Refresh DHCP + DNS** button is separate and explicit. It only flushes the DNS cache and renews the active adapter's DHCP lease when that adapter already uses DHCP.

## Command-line use

Run a diagnosis:

```powershell
.\windows-crash-doctor\NetworkDoctor.ps1
```

Run the rule-classification self-test:

```powershell
.\windows-crash-doctor\NetworkDoctor.ps1 -SelfTest
```

Explicitly refresh DNS cache + the current DHCP lease:

```powershell
.\windows-crash-doctor\NetworkDoctor.ps1 -Mode Refresh
```

## Future work

Useful next additions include:

- stronger route-metric / VPN-route conflict detection;
- parsed Wi-Fi association fields rather than raw `netsh` text;
- browser launch A/B tests such as QUIC-disabled diagnostics;
- Windows Filtering Platform / firewall attribution;
- packet-loss and DNS-latency sampling;
- side-by-side comparison against a previous Network Doctor run;
- optional export bundle with the same privacy review used by Crash Doctor.
