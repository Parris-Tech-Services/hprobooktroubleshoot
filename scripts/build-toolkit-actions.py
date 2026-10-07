"""Build curated launch/detection/action definitions; never execute toolkit commands."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / 'windows-crash-doctor/integrations/toolkit.tsv').open(encoding='utf-8') as source:
    tools = list(csv.DictReader(source, delimiter='\t'))
definitions = {t['name']: {'executables': [], 'arguments': [], 'actions': []} for t in tools}

def launch(name, executables, arguments=()):
    definitions[name]['executables'] = executables.split('|')
    definitions[name]['arguments'] = list(arguments)

def action(name, title, command, *, change=False, admin=False, timeout=45):
    definitions[name]['actions'].append(dict(name=title, command=command, changesSystem=change,
                                          requiresAdmin=admin, timeoutSeconds=timeout))

# Fixed launch arguments contain no user-provided command strings.
for name, command in {
    'Event Viewer':'eventvwr.msc', 'Resource Monitor':'resmon.exe', 'Task Manager':'taskmgr.exe',
    'Device Manager':'devmgmt.msc', 'System Information (msinfo32)':'msinfo32.exe', 'System Restore':'rstrui.exe',
    'Disk Management':'diskmgmt.msc', 'DirectX Diagnostic Tool (dxdiag)':'dxdiag.exe',
    'Performance Monitor':'perfmon.exe', 'Disk Cleanup':'cleanmgr.exe',
    'Defragment and Optimize Drives':'dfrgui.exe', 'Windows Memory Diagnostic':'mdsched.exe',
    'Resultant Set of Policy (rsop)':'rsop.msc', 'Windows Firewall Advanced Security':'wf.msc',
    'Registry Editor / reg.exe':'regedit.exe', 'Services / sc.exe':'services.msc',
    'Task Scheduler / schtasks':'taskschd.msc', 'System Configuration (msconfig)':'msconfig.exe',
    'Get-Tpm / tpm.msc':'tpm.msc', 'Quick Assist':'quickassist.exe', 'Windows Sandbox':'WindowsSandbox.exe',
}.items():
    if command.endswith('.msc'):launch(name,'mmc.exe',[command])
    else:launch(name,command)
launch('Reliability Monitor','perfmon.exe',['/rel'])
launch('Startup Repair','explorer.exe',['ms-settings:recovery'])
for name, command in {
    'Sysinternals Suite':'SysinternalsSuite\\procexp64.exe|procexp64.exe|procexp.exe',
    'Process Explorer':'procexp64.exe|procexp.exe', 'Autoruns':'Autoruns64.exe|Autoruns.exe',
    'Process Monitor (Procmon)':'Procmon64.exe|Procmon.exe', 'PsTools':'PsInfo64.exe|PsInfo.exe',
    'ProcDump':'procdump64.exe|procdump.exe', 'TCPView':'tcpview64.exe|tcpview.exe', 'RAMMap':'RAMMap64.exe|RAMMap.exe',
    'Sigcheck':'sigcheck64.exe|sigcheck.exe', 'BgInfo':'Bginfo64.exe|Bginfo.exe', 'Sysmon':'Sysmon64.exe|Sysmon.exe',
    'VMMap':'VMMap64.exe|VMMap.exe', 'Coreinfo':'Coreinfo64.exe|Coreinfo.exe', 'Handle':'handle64.exe|handle.exe',
    'ListDLLs':'listdlls64.exe|listdlls.exe', 'LiveKd':'livekd64.exe|livekd.exe', 'DebugView':'Dbgview64.exe|Dbgview.exe',
    'Disk2vhd':'disk2vhd64.exe|disk2vhd.exe', 'SDelete':'sdelete64.exe|sdelete.exe',
    'PsInfo':'PsInfo64.exe|PsInfo.exe', 'PsPing':'psping64.exe|psping.exe', 'DU':'du64.exe|du.exe',
    'CPU-Z':'CPUID\\CPU-Z\\cpuz.exe|cpuz.exe|cpuz_x64.exe', 'GPU-Z':'GPU-Z.exe',
    'HWMonitor':'CPUID\\HWMonitor\\HWMonitor.exe|HWMonitor.exe',
    'LibreHardwareMonitor':'librehardwaremonitor\\LibreHardwareMonitor.exe|LibreHardwareMonitor.exe',
    'HWiNFO64':'HWiNFO64\\HWiNFO64.exe|HWiNFO64.exe', 'Core Temp':'Core Temp\\Core Temp.exe|Core Temp.exe',
    'MSI Afterburner':'MSI Afterburner\\MSIAfterburner.exe|MSIAfterburner.exe',
    'LatencyMon':'LatencyMon\\LatMon.exe|LatMon.exe', 'CrystalDiskInfo':'CrystalDiskInfo\\DiskInfo64.exe|DiskInfo64.exe|DiskInfo.exe',
    'CrystalDiskMark':'CrystalDiskMark\\DiskMark64.exe|DiskMark64.exe|DiskMark.exe',
    'CrystalMark 3D25':'CrystalMark3D25\\CrystalMark3D25.exe|CrystalMark3D25.exe',
    'OCCT':'OCCT.exe', 'Prime95':'prime95.exe', 'FurMark':'Geeks3D\\FurMark\\FurMark.exe|FurMark.exe|FurMark_GUI.exe',
    'Cinebench':'Cinebench.exe', 'GSmartControl':'gsmartcontrol\\gsmartcontrol.exe|gsmartcontrol.exe',
    'HDDScan':'HDDScan.exe', 'BatteryInfoView':'BatteryInfoView.exe', 'PassMark MonitorTest':'MonitorTest.exe',
    'Keyboard / touchpad testers':'KeyboardTest.exe', 'Dell SupportAssist / ePSA':'Dell\\SupportAssistAgent\\bin\\SupportAssist.exe|SupportAssist.exe',
    'HP PC Hardware Diagnostics UEFI':'HP\\HP PC Hardware Diagnostics Windows\\HPDiags.exe|HPDiags.exe',
    'Lenovo Diagnostics':'Lenovo\\Lenovo Diagnostics\\LenovoDiagnostics.exe|LenovoDiagnostics.exe',
    'Vendor SSD utilities':'Samsung\\Samsung Magician\\SamsungMagician.exe|SamsungMagician.exe',
    'Microsoft PC Manager':'PCManager\\MSPCManager.exe|MSPCManager.exe',
    'CCleaner':'CCleaner\\CCleaner64.exe|CCleaner64.exe|CCleaner.exe',
    'BleachBit':'BleachBit\\bleachbit.exe|bleachbit.exe', 'WizTree':'WizTree\\WizTree64.exe|WizTree64.exe|WizTree.exe',
    'WinDirStat':'WinDirStat\\windirstat.exe|windirstat.exe',
    'Windows Performance Analyzer (WPA)':'Windows Kits\\10\\Windows Performance Toolkit\\wpa.exe|wpa.exe',
    'Windows Performance Recorder (WPR)':'wprui.exe|Windows Kits\\10\\Windows Performance Toolkit\\wprui.exe',
    'Windows Performance Toolkit (WPT)':'Windows Kits\\10\\Windows Performance Toolkit\\wpa.exe|wpa.exe',
    'GPUView':'Windows Kits\\10\\Windows Performance Toolkit\\gpuview.exe|gpuview.exe', 'Microsoft PIX':'WinPixGui.exe',
    'WinDbg / cdb':'WinDbgX.exe|Windows Kits\\10\\Debuggers\\x64\\cdb.exe|cdb.exe',
    'BlueScreenView':'BlueScreenView.exe', 'WhoCrashed':'WhoCrashed\\whocrashed.exe|whocrashed.exe',
    'DriverStore Explorer':'Rapr.exe', 'Double Driver':'dd.exe', 'Snappy Driver Installer Origin':'SDIO_x64.exe|SDIO.exe',
    'Wireshark':'Wireshark\\Wireshark.exe|Wireshark.exe', 'Nmap / Zenmap':'Nmap\\zenmap.exe|zenmap.exe|nmap.exe',
    'Advanced IP Scanner':'Advanced IP Scanner\\advanced_ip_scanner.exe|advanced_ip_scanner.exe',
    'Angry IP Scanner':'Angry IP Scanner\\ipscan.exe|ipscan.exe', 'PingPlotter':'PingPlotter.exe', 'WinMTR':'WinMTR.exe',
    'iperf3':'iperf3.exe', 'Fing':'Fing.exe', 'NetSpot':'NetSpot.exe', 'inSSIDer / Wi-Fi Analyzer alternatives':'inSSIDer.exe',
    'PuTTY':'PuTTY\\putty.exe|putty.exe', 'Tera Term':'teraterm\\ttermpro.exe|ttermpro.exe',
    'MobaXterm':'MobaXterm\\MobaXterm.exe|MobaXterm.exe', 'RustDesk':'RustDesk\\rustdesk.exe|rustdesk.exe',
    'AnyDesk':'AnyDesk\\AnyDesk.exe|AnyDesk.exe', 'PRTG':'PRTG Network Monitor\\PRTG Enterprise Console.exe',
    'Macrium Reflect':'Macrium\\Reflect\\Reflect.exe|Reflect.exe', 'Rufus':'rufus.exe',
    'TestDisk':'testdisk_win.exe', 'PhotoRec':'qphotorec_win.exe|photorec_win.exe',
    'Recuva':'Recuva\\recuva64.exe|recuva64.exe|recuva.exe', 'DMDE':'dmde.exe',
    'Malwarebytes':'Malwarebytes\\Anti-Malware\\mbam.exe|mbam.exe', 'AdwCleaner':'adwcleaner.exe',
    'Kaspersky Virus Removal Tool':'KVRT.exe', 'ESET Online Scanner':'esetonlinescanner.exe',
    'TDSSKiller':'TDSSKiller.exe', 'RKill':'rkill.exe', 'HitmanPro':'HitmanPro.exe|HitmanPro_x64.exe',
    'Microsoft Safety Scanner (MSERT)':'msert.exe',
    'Revo Uninstaller':'VS Revo Group\\Revo Uninstaller\\Revouninstaller.exe|Revouninstaller.exe',
    'Geek Uninstaller':'geek.exe', 'O&O ShutUp10++':'OOSU10.exe',
    'WinGet':'winget.exe', 'Chocolatey':'%ChocolateyInstall%\\bin\\choco.exe|choco.exe', 'Ninite':'Ninite.exe',
    'Everything':'Everything\\Everything.exe|Everything.exe', 'NirLauncher':'NirLauncher.exe',
    'USBDeview':'USBDeview.exe', 'DriverView':'DriverView.exe', 'CurrPorts':'cports.exe',
    'ShellExView':'shexview.exe', 'AppCrashView':'AppCrashView.exe', 'smartmontools':'smartmontools\\bin\\smartctl.exe|smartctl.exe',
}.items():launch(name,command)

for name, command in {
    'System File Checker (SFC)':'sfc.exe', 'DISM':'dism.exe', 'CHKDSK':'chkdsk.exe',
    'BCDEdit':'bcdedit.exe', 'BCDBoot':'bcdboot.exe', 'ReAgentC':'reagentc.exe', 'MBR2GPT':'mbr2gpt.exe',
    'DiskPart':'diskpart.exe', 'mountvol':'mountvol.exe', 'fsutil':'fsutil.exe', 'compact':'compact.exe',
    'Robocopy':'robocopy.exe', 'certutil -hashfile':'certutil.exe', 'Driver Verifier':'verifier.exe', 'PnPUtil':'pnputil.exe',
    'Netsh':'netsh.exe', 'pathping':'pathping.exe', 'nslookup / Resolve-DnsName':'nslookup.exe', 'PktMon':'pktmon.exe',
    'netsh trace':'netsh.exe', 'route print / arp -a / netstat -ano':'netstat.exe',
    'ipconfig /all, /flushdns, /registerdns':'ipconfig.exe', 'whoami /all':'whoami.exe', 'dsregcmd /status':'dsregcmd.exe',
    'MDMDiagnosticTool':'mdmdiagnosticstool.exe', 'manage-bde / Get-BitLockerVolume':'manage-bde.exe',
    'gpresult /h / Group Policy tools':'gpresult.exe',
}.items():
    launch(name,command,['/?'])
    definitions[name]['consoleHint'] = 'Command-line tool: use the diagnostic action below, or launch help before selecting an advanced operation.'
for tool in tools:
    name=tool['name']
    if name.startswith('powercfg '):launch(name,'powercfg.exe',['/?'])
    if name.startswith('Get-') or name in ('Test-NetConnection','Confirm-SecureBootUEFI'):
        launch(name,'%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoProfile','-NoExit'])
for name, uri in [('Storage Sense','ms-settings:storagesense'),('Get Help / Settings Troubleshooters','ms-settings:troubleshoot')]:
    launch(name,'explorer.exe',[uri])

readonly={
    'System File Checker (SFC)':('Verify protected system files','sfc.exe /verifyonly',True,1800),
    'DISM':('Check Windows image health','dism.exe /Online /Cleanup-Image /CheckHealth',True,180),
    'CHKDSK':('Read-only system-drive filesystem check','chkdsk.exe $env:SystemDrive',True,1800),
    'BCDEdit':('Inspect boot configuration','bcdedit.exe /enum',True,45),
    'ReAgentC':('Inspect Windows Recovery Environment','reagentc.exe /info',True,45),
    'MBR2GPT':('Validate conversion readiness only','mbr2gpt.exe /validate /allowFullOS',True,90),
    'Event Viewer':('Recent critical/error events',"Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddDays(-2)} -MaxEvents 100 | Select-Object TimeCreated,Id,ProviderName,Message | Format-List",False,45),
    'Reliability Monitor':('Reliability history','Get-CimInstance Win32_ReliabilityRecords | Sort-Object TimeGenerated -Descending | Select-Object -First 100 TimeGenerated,SourceName,EventIdentifier,Message | Format-List',False,45),
    'Resource Monitor':('Process resource snapshot','Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Name,Id,CPU,WorkingSet64,Handles | Format-Table -AutoSize',False,45),
    'Task Manager':('Process and startup inventory','Get-Process | Select-Object Name,Id,CPU,WorkingSet64 | Format-Table -AutoSize; Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | Format-List',False,45),
    'Device Manager':('Devices with reported faults','Get-PnpDevice | Where-Object Status -ne OK | Select-Object Status,Class,FriendlyName,InstanceId | Format-List',False,45),
    'Disk Management':('Disk and volume inventory','Get-Disk | Format-List Number,FriendlyName,PartitionStyle,OperationalStatus,Size; Get-Volume | Format-Table DriveLetter,FileSystem,HealthStatus,Size,SizeRemaining',False,45),
    'System Information (msinfo32)':('Hardware and operating system inventory','Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer,Model,TotalPhysicalMemory; Get-CimInstance Win32_BIOS | Format-List Manufacturer,SMBIOSBIOSVersion,ReleaseDate; Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber',False,45),
    'System Restore':('List restore points','Get-ComputerRestorePoint | Format-List',True,60),
    'Get-PhysicalDisk':('Physical disk health','Get-PhysicalDisk | Format-List FriendlyName,SerialNumber,MediaType,HealthStatus,OperationalStatus,Size',False,45),
    'Get-StorageReliabilityCounter':('Storage reliability counters','Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-List',True,60),
    'Get-Disk / Get-Volume / Get-Partition':('Storage topology','Get-Disk | Format-List; Get-Partition | Format-Table; Get-Volume | Format-Table',False,60),
    'mountvol':('Volume mount points','mountvol.exe',False,45),
    'fsutil':('Query filesystem dirty bit and TRIM','fsutil.exe dirty query $env:SystemDrive; fsutil.exe behavior query DisableDeleteNotify',True,45),
    'compact':('Query CompactOS state','compact.exe /CompactOS:query',False,45),
    'Driver Verifier':('Inspect active verifier settings','verifier.exe /querysettings',True,45),
    'PnPUtil':('Enumerate driver-store packages','pnputil.exe /enum-drivers',False,45),
    'Get-PnpDevice':('Device status inventory','Get-PnpDevice | Select-Object Status,Class,FriendlyName,InstanceId | Format-List',False,45),
    'Get-WinEvent filtering':('Recent application errors',"Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddDays(-2)} -MaxEvents 100 | Format-List TimeCreated,Id,ProviderName,Message",False,45),
    'Get-CimInstance / Get-WmiObject':('CIM hardware inventory','Get-CimInstance Win32_Processor | Format-List Name,NumberOfCores,NumberOfLogicalProcessors; Get-CimInstance Win32_PhysicalMemory | Format-Table Manufacturer,Capacity,Speed,PartNumber',False,45),
    'Netsh':('Network configuration snapshot','netsh.exe interface ipv4 show config',False,45),
    'nslookup / Resolve-DnsName':('DNS resolver configuration','Get-DnsClientServerAddress | Format-List; Resolve-DnsName microsoft.com | Format-Table',False,45),
    'PktMon':('Packet-monitor status','pktmon.exe status',True,45),
    'netsh trace':('Network trace status','netsh.exe trace show status',True,45),
    'Test-NetConnection':('Microsoft HTTPS connectivity','Test-NetConnection www.microsoft.com -Port 443 -InformationLevel Detailed | Format-List',False,60),
    'Get-NetAdapter':('NIC state and driver inventory','Get-NetAdapter | Format-List Name,InterfaceDescription,Status,LinkSpeed,DriverInformation',False,45),
    'Get-NetTCPConnection':('TCP endpoints and process IDs','Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize',False,45),
    'route print / arp -a / netstat -ano':('Routing and socket snapshot','route.exe print; arp.exe -a; netstat.exe -ano',False,45),
    'ipconfig /all, /flushdns, /registerdns':('IP configuration','ipconfig.exe /all',False,45),
    'whoami /all':('Token, groups and privileges','whoami.exe /all',False,45),
    'dsregcmd /status':('Entra device registration state','dsregcmd.exe /status',False,45),
    'gpresult /h / Group Policy tools':('Applied policy summary','gpresult.exe /r',False,60),
    'manage-bde / Get-BitLockerVolume':('BitLocker state without recovery secrets','Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod | Format-List',True,45),
    'Get-Tpm / tpm.msc':('TPM readiness','Get-Tpm | Format-List',False,45),
    'Confirm-SecureBootUEFI':('Secure Boot status','Confirm-SecureBootUEFI',True,45),
    'Get-MpComputerStatus / Start-MpScan':('Defender health','Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge | Format-List',False,45),
    'Windows Firewall Advanced Security':('Firewall profile status','Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-List',False,45),
    'Services / sc.exe':('Service state inventory','Get-Service | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize',False,45),
    'Task Scheduler / schtasks':('Scheduled task inventory','Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize',False,45),
    'powercfg /requests':('Sleep blockers','powercfg.exe /requests',True,45),
    'powercfg /lastwake':('Last wake source','powercfg.exe /lastwake',False,45),
    'WinGet':('Installed package inventory','winget.exe list --disable-interactivity',False,90),
    'Chocolatey':('Installed package inventory','choco.exe list --limit-output',False,60),
    'PSWindowsUpdate':('Installed update module version','Get-Module -ListAvailable PSWindowsUpdate | Select-Object Name,Version,Path | Format-List',False,45),
    'Windows Sandbox':('Sandbox feature availability',"Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM | Format-List FeatureName,State",True,45),
    'RSAT':('RSAT feature availability',"Get-WindowsCapability -Online | Where-Object Name -like 'RSAT*' | Format-Table Name,State",True,60),
}
for name,(title,command,admin,timeout) in readonly.items():action(name,title,command,admin=admin,timeout=timeout)
for name in ['Get-WinEvent filtering','Get-CimInstance / Get-WmiObject','PSWindowsUpdate','RSAT','Get-MpComputerStatus / Start-MpScan']:
    launch(name,'%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoProfile','-NoExit'])

for name,title,command in [
    ('System File Checker (SFC)','Repair protected Windows files','sfc.exe /scannow'),
    ('DISM','Repair Windows image','dism.exe /Online /Cleanup-Image /RestoreHealth'),
    ('DISM','Scan Windows image health','dism.exe /Online /Cleanup-Image /ScanHealth'),
    ('CHKDSK','Schedule system-drive filesystem repair','chkdsk.exe $env:SystemDrive /f'),
    ('CHKDSK','Schedule system-drive filesystem and sector recovery','chkdsk.exe $env:SystemDrive /r'),
    ('ipconfig /all, /flushdns, /registerdns','Flush DNS cache','ipconfig.exe /flushdns'),
    ('ipconfig /all, /flushdns, /registerdns','Register DNS records','ipconfig.exe /registerdns'),
    ('Get-MpComputerStatus / Start-MpScan','Run Defender quick scan','Start-MpScan -ScanType QuickScan'),
    ('Windows Defender Offline scan','Restart into Defender Offline scan','Start-MpWDOScan'),
    ('ReAgentC','Enable Windows Recovery Environment','reagentc.exe /enable'),
]:action(name,title,command,change=True,admin=True,timeout=3600)

# Diagnostic artifacts are written only into the per-action working directory.
for name,title,command,admin,timeout in [
    ('DirectX Diagnostic Tool (dxdiag)','Export DirectX diagnostic report',"Start-Process dxdiag.exe -ArgumentList @('/t',(Join-Path (Get-Location) 'dxdiag.txt')) -Wait -NoNewWindow; Get-Content -LiteralPath 'dxdiag.txt'",False,90),
    ('powercfg /batteryreport','Export battery report',"powercfg.exe /batteryreport /output (Join-Path (Get-Location) 'battery-report.html')",False,60),
    ('powercfg /energy','Capture 15-second energy report',"powercfg.exe /energy /duration 15 /output (Join-Path (Get-Location) 'energy-report.html')",True,60),
    ('powercfg /sleepstudy','Export sleep study',"powercfg.exe /sleepstudy /output (Join-Path (Get-Location) 'sleep-study.html')",True,60),
    ('powercfg /systempowerreport','Export power-transition report',"powercfg.exe /systempowerreport /output (Join-Path (Get-Location) 'system-power-report.html')",True,60),
    ('MDMDiagnosticTool','Collect local MDM diagnostic bundle',"mdmdiagnosticstool.exe -area 'DeviceEnrollment;DeviceProvisioning;Autopilot' -zip (Join-Path (Get-Location) 'mdm-diagnostics.zip')",True,180),
]:action(name,title,command,admin=admin,timeout=timeout)

for name,provider in [('LibreHardwareMonitor','librehardwaremonitor'),('smartmontools','smartmontools')]:definitions[name]['providerId']=provider
for name in ('SDelete','Sysmon','ProcDump','PsTools','PsInfo','PsPing','DU','Handle','ListDLLs','Sigcheck','Coreinfo','LiveKd','iperf3'):
    definitions[name]['arguments']=['-?'] if name!='iperf3' else ['--help']
launch('smartmontools','smartmontools\\bin\\smartctl.exe|smartctl.exe',['--help'])
launch('Get-WindowsAutopilotInfo','%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoProfile','-NoExit'])
action('Get-WindowsAutopilotInfo','Inspect Autopilot script availability',"Get-InstalledScript -Name Get-WindowsAutopilotInfo -ErrorAction Stop | Select-Object Name,Version,InstalledLocation | Format-List")
action('WinDbg / cdb','Inspect debugger symbols',"[pscustomobject]@{ProcessSymbolPath=$env:_NT_SYMBOL_PATH;UserSymbolPath=[Environment]::GetEnvironmentVariable('_NT_SYMBOL_PATH','User')} | Format-List")
action('WinDbg / cdb','Configure Microsoft symbol server',"$cache=Join-Path $env:LOCALAPPDATA 'WindowsCrashDoctor\\symbols'; New-Item -ItemType Directory -Path $cache -Force | Out-Null; $value='srv*'+$cache+'*https://msdl.microsoft.com/download/symbols'; [Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH',$value,'User'); Write-Output $value",change=True)
action('LibreHardwareMonitor','Capture current hardware sensors',"Import-Module (Join-Path $env:LOCALAPPDATA 'WindowsCrashDoctor\\engine\\0.3.0\\windows-crash-doctor\\Integrations.psm1') -Force; Get-WcdHardwareSensors | ConvertTo-Json -Depth 6",timeout=60)
action('smartmontools','List SMART-capable devices',"smartctl.exe --scan-open",admin=True,timeout=60)
action('pathping','Trace route and loss to Microsoft',"pathping.exe -q 10 -p 100 www.microsoft.com",timeout=120)

destination=ROOT/'windows-crash-doctor/integrations/toolkit-actions.json'
destination.write_text(json.dumps(definitions,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(f'{len(definitions)} tool definitions; {sum(bool(d["executables"]) for d in definitions.values())} launch mappings; {sum(len(d["actions"]) for d in definitions.values())} diagnostic/action recipes.')
