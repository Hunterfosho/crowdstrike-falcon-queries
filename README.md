# crowdstrike-falcon-queries

<img src="https://img.shields.io/github/last-commit/hunterfosho/crowdstrike-falcon-queries.svg"/> </p>

**A collection of Splunk's Search Processing Language (SPL) for Threat Hunting with CrowdStrike Falcon**

>Developed and maintained by [HunterfoSho](https://github.com/Hunterfosho/crowdstrike-falcon-queries) forked from [pe3zx](https://github.com/pe3zx/crowdstrike-falcon-queries) Master Repo
>
>Additional credit and huge shoutout to the cs engneering team at [r/crowdstrike](https://www.reddit.com/r/crowdstrike/?f=flair_name%3A%22CQF%22)

- [crowdstrike-falcon-queries](#crowdstrike-falcon-queries)
  - [Execution of Renamed Executables](#execution-of-renamed-executables)
  - [List of Living Off The Land Binaries with Network Connections](#list-of-living-off-the-land-binaries-with-network-connections)
  - [Suspicious Network Connections from Processes](#suspicious-network-connections-from-processes)
  - [Suspicious PowerShell Process, Spawned from Explorer, with Network Connections](#suspicious-powershell-process-spawned-from-explorer-with-network-connections)
  - [RDP Hijacking traces](#rdp-hijacking-traces)
  - [Basic UserLogon and ComputerName](#basic-userlogon-and-computername)
  - [Detecting USB Devices](#detecting-usb-devices)
  - [Detecting Known Commands by ComputerName](#detecting-known-commands-by-computername)
  - [Detecting CMD.exe commandLine activity NOT running from temp directories](#detecting-cmdexe-commandline-activity-not-running-from-temp-directories)
  - [Detecting Files Written to USB Device](#detecting-files-written-to-usb-device)
  - [Detecting EOL WIN10 Devices](#detecting-eol-win10-devices)
  - [Detecting DNS Request by DomainName](#detecting-dns-request-by-domainname)
  - [Adjust Timebased Searches OffsetUTC by Local Time](#adjust-timebased-searches-offsetutc-by-local-time)
  - [Micrsoft Office Macro Hunting Queries](#micrsoft-office-macro-hunting-queries)
  - [Detecting Remote Network Connections by ComputerName](#detecting-remote-network-connections-by-computername)
  - [Hunting USB and Removeable Device](#hunting-usb-and-removeable-device)
  - [Get A Quick Count of Endpoints by CID](#get-a-quick-count-of-endpoints-by-cid)
  - [Hunting for Falcon Sensor Removal](#hunting-for-falcon-sensor-removal)
  - [MAC Devices](#mac-devices)
  - [Hunting UserLogon Events](#hunting-userlogon-events)
- [Hunting Linux](#hunting-linux)
  - [The same remote IP address having more than one failed login attempt](#the-same-remote-ip-address-having-more-than-one-failed-login-attempt)
  - [The same remote IP address having more than one failed login attempt against the same username](#the-same-remote-ip-address-having-more-than-one-failed-login-attempt-against-the-same-username)
  - [The same username against a single or multiple systems the point of interest](#the-same-username-against-a-single-or-multiple-systems-the-point-of-interest)
  - [Successful Audit Login](#successful-audit-login)
  - [Hunting Linux RFM](#hunting-linux-rfm)
  - [Discover RFM State](#discover-rfm-state)
  - [UserPassword Greater than 90days by UserLogon](#userpassword-greater-than-90days-by-userlogon)
  - [Hunting Known Commands](#hunting-known-commands)

## Execution of Renamed Executables

>This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

>Idea:

- Identify if there are any events with file renaming activity � found that CrowdStrike Falcon already had a specific field name for executables, `NewExecutableRenamed`.
- Correlate `TargetFileName` field on `NewExecutableRenamed` event with a filename available on `ImageFileName` field on `ProcessRollup2` event.
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, and `CommandLine` as columns.

```
event_simpleName="NewExecutableRenamed"
| rename TargetFileName as ImageFileName
| join ImageFileName 
    [ search event_simpleName="ProcessRollup2" ]
| table ComputerName SourceFileName ImageFileName CommandLine
```

## List of Living Off The Land Binaries with Network Connections

>This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

>Idea:

- Identify if there are any events relating to network activity � found that CrowdStrike Falcon has `DnsRequest` and `NetworkConnectIP4` events. We�re going to use the `DnsRequest` event in this query.
- Correlate `ContextProcessId` field from `DnsRequest` event with `TargetProcessId` on `ProcessRollup2` event.
- Create a sub-search to filter only known LOLBas files.
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, and `CommandLine` as columns. 

>Because our hunting query required a list of known LOL binaries/files for filtering, we need to enumerate a list of files available on [LOLBAS-Project/LOLBas](https://github.com/LOLBAS-Project/LOLBAS), which can simple by done by a `grep` expression: `grep -Poh "(?<=Name:\s)[A-Za-z0-9_-]+.exe$" OSBinaries/`

```
event_simpleName="DnsRequest"
| rename ContextProcessId as TargetProcessId
| join TargetProcessId 
    [ search event_simpleName="ProcessRollup2" (FileName=Atbroker.exe OR FileName=Bash.exe OR FileName=Bitsadmin.exe OR FileName=Certutil.exe OR FileName=Cmd.exe OR FileName=Cmstp.exe OR FileName=Control.exe OR FileName=Cscript.exe OR FileName=Csc.exe OR FileName=Dfsvc.exe OR FileName=Diskshadow.exe OR FileName=Dnscmd.exe OR FileName=Esentutl.exe OR FileName=Eventvwr.exe OR FileName=Expand.exe OR FileName=Extexport.exe OR FileName=Extrac32.exe OR FileName=Findstr.exe OR FileName=Forfiles.exe OR FileName=Ftp.exe OR FileName=Gpscript.exe OR FileName=Hh.exe OR FileName=Ie4uinit.exe OR FileName=Ieexec.exe OR FileName=Infdefaultinstall.exe OR FileName=Installutil.exe OR FileName=Jsc.exe OR FileName=Makecab.exe OR FileName=Mavinject.exe OR FileName=Mmc.exe OR FileName=Msconfig.exe OR FileName=Msdt.exe OR FileName=Mshta.exe OR FileName=Msiexec.exe OR FileName=Odbcconf.exe OR FileName=Pcalua.exe OR FileName=Pcwrun.exe OR FileName=Presentationhost.exe OR FileName=Print.exe OR FileName=Regasm.exe OR FileName=Regedit.exe OR FileName=Register-cimprovider.exe OR FileName=Regsvcs.exe OR FileName=Regsvr32.exe OR FileName=Reg.exe OR FileName=Replace.exe OR FileName=Rpcping.exe OR FileName=Rundll32.exe OR FileName=Runonce.exe OR FileName=Runscripthelper.exe OR FileName=Schtasks.exe OR FileName=Scriptrunner.exe OR FileName=Sc.exe OR FileName=SyncAppvPublishingServer.exe OR FileName=Verclsid.exe OR FileName=Wab.exe OR FileName=Wmic.exe OR FileName=Wscript.exe OR FileName=Wsreset.exe OR FileName=Xwizard.exe) ] 
| table ComputerName timestamp ImageFileName DomainName CommandLine 
```

## Suspicious Network Connections from Processes

>This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).

>Idea:

- Identify network activities recorded by CrowdStrike falcon with the `DNSRequest` or `NetworkConnectIP4` event, in this query we will use `NetworkConnectIP4`.
- Correlate `ContextProcessId_decimal` with `TargetProcessId_decimal` on `ProcessRollup2` events
- Create a result table with `RemoteIP`, `RemotePort_decimal`, `ImageFileName`, `UserName` and `UserSid_readable`.

```
event_simpleName="NetworkConnectIP4"
| rename ContextProcessId_decimal as TargetProcessId_decimal
| join TargetProcessId_decimal 
    [ search event_simpleName=ProcessRollup2 ]
| table RemoteIP RemotePort_decimal ImageFileName UserName UserSid_readabl
```

## Suspicious PowerShell Process, Spawned from Explorer, with Network Connections

>This query is inspired by [Red Canary's research](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/). For explanation in Thai, please find in [our blog](https://www.i-secure.co.th/2019/11/practicing-threat-hunting-skills-with-crowdstrike-events-app/).
>
>Idea:

- Identify network activities recorded by CrowdStrike falcon with the `DNSRequest` event
- Correlate `ContextProcessId` field on `DNSRequest` with `TargetProcessId` on `ProcessRollup2` and `SyntheticProcessRollup2` events
- With a combination of *rename-join-subsearch*, the outer nested sub-search will be created and responsible for identifying a `TargetProcessId_decimal` of `Explorer.exe` from `ProcessRollup2` event, and then join with the inner nested sub-search that responsible to find `PowerShell.exe` which has the same `ParentProcessId_decimal` as `TargetProcessId_decimal` of `Explorer.exe`
- Create a result table with `ComputerName`, `timestamp`, `ImageFileName`, `DomainName`, and `CommandLine`

>Be aware that whenever `ParentProcessId_decimal` is used, you may need to extend a search scope longer than usual. Because some processes, especially system processes, usually have high uptime but been abused recently.

```
event_simpleName="DnsRequest"
| rename ContextProcessId as TargetProcessId
| join TargetProcessId 
    [ search (event_simpleName="ProcessRollup2" OR event_simpleName="SyntheticProcessRollup2") AND FileName="explorer.exe" 
    | rename TargetProcessId_decimal as ParentProcessId_decimal 
    | join ParentProcessId_decimal 
        [ search event_simpleName="ProcessRollup2" FileName="powershell.exe" ]] 
| table ComputerName timestamp ImageFileName DomainName CommandLine
```

## RDP Hijacking traces

>This query is inspired by [MENASEC's research](https://blog.menasec.net/2019/02/of-rdp-hijacking-part1-remote-desktop.html).
>
>CrowdStrike has an event category named `RegSystemConfigValueUpdate` for this kind of behavior. However, `LastLoggedOnUser` and `LastLoggedOnSAMUser` aren't considered a system config. So, we can find an attempt to edit `RDP-Tcp\PortNumber` only.

```
event_simpleName="RegSystemConfigValueUpdate" AND RegObjectName="*\RDP-Tcp" AND RegValueName="PortNumber" 
| rename RegNumericValue_decimal as "NewRDPPort"
| table timestamp, ComputerName, NewRDPPort
```

## Basic UserLogon and ComputerName

>Enter a username between the ()

```
UserName=() event_simpleName=UserLogon
| table ComputerName 
| dedup ComputerName
```

## Detecting USB Devices

```
event_simpleName=DcUsbDeviceConnected DevicePropertyDeviceDescription="USB Mass Storage Device"
| eval CloudTime=strftime(timestamp/1000, "%Y-%m-%d %H:%M:%S.%3f")
| rename ComputerName AS Hostname, DevicePropertyClassName AS "Connection Type", DeviceManufacturer AS Manufacturer, DeviceProduct AS "Product Name", DevicePropertyDeviceDescription AS Description, DevicePropertyClassGuid_readable AS GUID, DeviceInstanceId AS "Device ID"
| stats list(CloudTime) by Hostname "Connection Type" Manufacturer "Product Name" Description GUID "Device ID"
```
## Detecting Known Commands by ComputerName

>This can be performed with either of the commands below.

```
ComputerName=*  event_simpleName=ProcessRollup2 (FileName=net.exe OR FileName=ipconfig.exe OR FileName=whoami.exe OR FileName=quser.exe OR FileName=ping.exe OR FileName=netstat.exe OR FileName=tasklist.exe OR FileName=Hostname.exe OR FileName=at.exe) | table ComputerName UserName FileName CommandLine
```

```
ComputerName=* event_simpleName=ProcessRollup2 FileName IN (net.exe,ipconfig.exe,whoami.exe,quser.exe,ping.exe,netstat.exe,tasklist.exe,Hostname.exe,at.exe) 
| table ComputerName UserName FileName CommandLine
```

## Detecting CMD.exe commandLine activity NOT running from temp directories

>This query detects commandline cmd.exe activity by clustering the files triggered

```
FileName=cmd.exe event_simpleName=ProcessRollup2 CommandLine!="*Windows\\TEMP\\xtmp\\tmp*" CommandLine!="*AppData\\Local\\Temp\\cstmp*"
| cluster field=CommandLine labelonly=true t=0.9
| stats values(ComputerName) values(CommandLine) by cluster_label
```

## Detecting Files Written to USB Device

```
event_simpleName=* FileWritten IsOnRemovableDisk_decimal=1
| rename DiskParentDeviceInstanceId AS DeviceInstanceId
| join aid DeviceInstanceId [search event_simpleName=DcUsbDeviceConnected]
| rename ComputerName AS Hostname, DevicePropertyClassName AS "Connection Type", DeviceManufacturer AS Manufacturer, DeviceProduct AS "Product Name", DevicePropertyDeviceDescription AS Description, DeviceInstanceId AS "Device ID"
| stats list(FileName) as "File Name", values(UserName) as User by Hostname "Connection Type" Manufacturer "Product Name" Description "Device ID"
```

## Detecting EOL WIN10 Devices

```
earliest=-7d event_simpleName=OsVersionInfo MajorVersion_decimal=10 MinorVersion_decimal=0 ProductType_decimal=1
| dedup aid
| rename BuildNumber_decimal as "WindowsBuildVersion"
| eval WindowsBuild=case(WindowsBuildVersion == 17134, "Windows 10 (v1803)", WindowsBuildVersion == 18363, "Windows 10 (v1909)", WindowsBuildVersion == 18362, "Windows 10 (v1903)", WindowsBuildVersion == 16299, "Windows 10 (v1709)", WindowsBuildVersion == 15063, "Windows 10 (v1703)", WindowsBuildVersion == 10586, "Windows 10 (v1511)", WindowsBuildVersion == 19041, "Windows 10 (v2004)")
| table ComputerName aid ProductName WindowsBuild AgentVersion
| stats count by WindowsBuild ComputerName
| sort - count
```

## Detecting DNS Request by DomainName

>I am using github as the example, but you can enter any domain name in the ().

```
event_simpleName=DnsRequest DomainName IN (raw.githubusercontent.com)
| table ComputerName DomainName ContextTimeStamp_decimal 
| eval ContextTimeStamp_readable=strftime(ContextTimeStamp_decimal, "%Y-%m-%d %H:%M:%S.%3f")
```

## Adjust Timebased Searches OffsetUTC by Local Time

>Falcon outputs time in UTC, you can enter your UTCoffset in side the () below.
>
>In the USA you can find out more about UTC and your specific offset [here](https://www.countries-ofthe-world.com/time-zones-usa.html).

```
event_simpleName IN (ProcessRollup2) ComputerName=()
| eval myUTCoffset=()
| eval myLocalTime=ProcessStartTime_decimal+(myUTCoffset*60*60)
| table FileName _time ProcessStartTime_decimal myLocalTime
| rename ProcessStartTime_decimal as endpointSystemClockUTC, _time as cloudTimeUTC
| convert ctime(cloudTimeUTC), ctime(endpointSystemClockUTC), ctime(myLocalTime)
```

## Micrsoft Office Macro Hunting Queries

>Microsoft Excel, Word and Powerpoint Macro SearchThis query will return the following information: ComputerName FileName ParentCommandLine ParentImageFileName FilePath ScriptingLanguageId ScriptContent. This query will also output the macro itself and language of the macro**

```
event_simpleName=ScriptControlScanTelemetry (FileName="EXCEL.EXE" OR FileName="WINWORD.EXE" OR FileName="POWERPNT.EXE") ScriptContent="*" | eval CloudTime=strftime(timestamp/1000, "%Y-%m-%d %H:%M:%S") | eval ScriptingLanguageId=case(ScriptingLanguageId_decimal="1", "UNKNOWN", ScriptingLanguageId_decimal="2", "POWERSHELL", ScriptingLanguageId_decimal="3", "VBA", ScriptingLanguageId_decimal="4", "VBS", ScriptingLanguageId_decimal="5", "JSCRIPT", ScriptingLanguageId_decimal="6", "DOTNET", ScriptingLanguageId_decimal="7", "EXCEL") | table CloudTime ComputerName ParentCommandLine FileName ScriptContentName ScriptingLanguageId ScriptContent
```

>Microsoft Excel, Word and Powerpoint Macro Enabled File SavedThis query will return the following information: ComputerName UserName FileName FilePath of any MS Office file with the following extensions: *.xlsm OR *.xlam OR *.xlsb OR *.xltm OR *.xlw OR *.docm OR *.dotm OR *.pptm OR *.potm OR *.ppam OR *.ppsm OR *.ppsx**

```
event_simpleName=OoxmlFileWritten (FileName=*.xla OR FileName*.xlm OR FileName=*.xltm OR FileName=*.xlsm OR FileName=*.xlam OR FileName=*.xlsb OR FileName=*.xltm OR FileName=*.xlw OR FileName=*.docm OR FileName=*.dotm OR FileName=*.pptm OR FileName=*.potm OR FileName=*.ppam OR FileName=*.ppsm OR FileName=*.ppsx OR FileName=*.sldm OR FileName=*.ACCDE) | eval CloudTime=strftime(timestamp/1000, "%Y-%m-%d %H:%M:%S") | table CloudTime ComputerName UserName FileName FilePath
```

## Detecting Remote Network Connections by ComputerName

>This search will allow you to see remote network connections by computer name. Please enter the computer name inside the () below.

```
index=main event_simpleName=NetworkConnectIP4 cid=* ComputerName=()
          | search LocalAddressIP4 IN (*) AND aip IN (*) AND RemoteAddressIP4 IN (*)
          | stats values(ComputerName) AS "Host Name", count AS Count, dc(ComputerName) AS "# of Hosts", last(ComputerName) AS "First Connection", min(_time) AS "First Connect Date", latest(ComputerName) AS "Last Connection", max(_time) AS "Last Connect Date", values(LocalAddressIP4) AS "Source IP", values(aip) AS "External IP" by RemoteAddressIP4  
          | where Count <= 1
          | dedup RemoteAddressIP4
          | convert ctime("First Connect Date")
          | convert ctime("Last Connect Date")
          | table "Source IP", RemoteAddressIP4, "External IP", "Host Name", "# of Hosts", "First Connection", "First Connect Date", "Last Connection", "Last Connect Date"
          | rename RemoteAddressIP4 AS "Destination IP"
```
## Hunting USB and Removeable Device

```
event_simpleName=DcUsbDeviceConnected DevicePropertyDeviceDescription="USB Mass Storage Device"
| eval CloudTime=strftime(timestamp/1000, "%Y-%m-%d %H:%M:%S.%3f")
| rename ComputerName AS Hostname, DevicePropertyClassName AS "Connection Type", DeviceManufacturer AS Manufacturer, DeviceProduct AS "Product Name", DevicePropertyDeviceDescription AS Description, DevicePropertyClassGuid_readable AS GUID, DeviceInstanceId AS "Device ID"
| stats list(CloudTime) by Hostname "Connection Type" Manufacturer "Product Name" Description GUID "Device ID"

index=main AND eventtype=eam AND event_simpleName=*FileWritten AND IsOnRemovableDisk_decimal=1
| rename event_platform as OperatingSystem, aip as PublicIP 
| table _time,ComputerName,OperatingSystem,LocalAddressIP4,PublicIP,UserName,IsOnRemovableDisk_decimal,event_simpleName,DiskParentDeviceInstanceId,FilePath,TargetFileName

event_platform=win ComputerName=* event_simpleName=*FileWritten | fields aid, ComputerName, ContextProcessId_decimal, ContextTimeStamp_decimal, TargetFileName, Size_decimal | rename TargetFileName AS writtenFile | rename ContextProcessId_decimal AS TargetProcessId_decimal | join aid, TargetProcessId_decimal [search event_platform=win event_simpleName=ProcessRollup2 | fillnull value="SYSTEM" UserName] | convert ctime(ContextTimeStamp_decimal) AS writeTime | eval fileSize=round(((Size_decimal/1024)/1024), 2) | table writeTime ComputerName UserName FileName writtenFile fileSize | rename writeTime AS "Write Time", ComputerName AS Endpoint, UserName AS User, FileName AS "Responsible Process", writtenFile AS "File Written", fileSize AS "File Size"

event_simpleName=* FileWritten IsOnRemovableDisk_decimal=1
| rename DiskParentDeviceInstanceId AS DeviceInstanceId
| join aid DeviceInstanceId [search event_simpleName=DcUsbDeviceConnected]
| rename ComputerName AS Hostname, DevicePropertyClassName AS "Connection Type", DeviceManufacturer AS Manufacturer, DeviceProduct AS "Product Name", DevicePropertyDeviceDescription AS Description, DeviceInstanceId AS "Device ID"
| stats list(FileName) as "File Name", values(UserName) as User by Hostname "Connection Type" Manufacturer "Product Name" Description "Device ID"
```
## Get A Quick Count of Endpoints by CID

```
| inputlookup aid_master
| stats dc(aid) as endpointCount by cid
| lookup cid_name cid OUTPUT name 
| sort - endpointCount
```

## Hunting for Falcon Sensor Removal

```
Hunting for Falcon Sensor Removal
event_platform=win event_simpleName=ProcessRollup2 ParentBaseFileName=cmd.exe FileName=msiexec.exe 
| regex CommandLine=".+\\\Package\s+Cache\\\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]v\d+\.\d+\.\d+\.\d+\\\(CsAgent.*|CsDeviceControl|CsFirmwareAnalysis)\.msi\"\s+REMOVE\=ALL"
| lookup local=true aid_master aid OUTPUT AgentVersion, Version
| eval ProcExplorer=case(TargetProcessId_decimal!="","https://falcon.crowdstrike.com/investigate/process-explorer/" .aid. "/" . TargetProcessId_decimal)
| table ProcessStartTime_decimal aid LocalAddressIP4 ComputerName aip Version AgentVersion UserName ParentBaseFileName FileName CommandLine ProcExplorer
| convert ctime(ProcessStartTime_decimal)
| rename ProcessStartTime_decimal as systemClockUTC, aid as agentID, LocalAddressIP4 as localIP, aip as externalIP, Version as osVersion, AgentVersion as agentVersion, UserName as userName, ParentBaseFileName as parentFile, FileName as fileName, CommandLine as cmdLine, ProcExplorer as processExplorerLink
```

## MAC Devices

```
event_platform=mac sourcetype=HostInfo* event_simpleName=HostInfo 
| where isnotnull(AnalyticsAndImprovementsIsSet_decimal)
| stats latest(AnalyticsAndImprovementsIsSet_decimal) as AnalyticsAndImprovementsIsSet, latest(ApplicationFirewallIsSet_decimal) as ApplicationFirewallIsSet, latest(AutoUpdate_decimal) as AutoUpdate, latest(FullDiskAccessForFalconIsSet_decimal) as FullDiskAccessForFalconIsSet, latest(FullDiskAccessForOthersIsSet_decimal) as FullDiskAccessForOthersIsSet, latest(GatekeeperIsSet_decimal) as GatekeeperIsSet, latest(InternetSharingIsSet_decimal) as InternetSharingIsSet, latest(PasswordRequiredIsSet_decimal) as PasswordRequiredIsSet, latest(RemoteLoginIsSet_decimal) as RemoteLoginIsSet, latest(SIPIsEnabled_decimal) as SIPIsEnabled, latest(StealthModeIsSet_decimal) as StealthModeIsSet by aid
|  eval remediationAnalytic=case(AnalyticsAndImprovementsIsSet=1, "Disable Analytics and Improvements in macOS")
|  eval remediationFirewall=case(ApplicationFirewallIsSet=0, "Enable Application Firewall")
|  eval remediationUpdate=case(AutoUpdate!=31, "Check macOS Update Settings")
|  eval remediationFalcon=case(FullDiskAccessForFalconIsSet=0, "Enable Full Disk Access for Falcon")
|  eval remediationGatekeeper=case(GatekeeperIsSet=0, "Enable macOS Gatekeeper")
|  eval remediationInternet=case(InternetSharingIsSet=1, "Disable Internet Sharing")
|  eval remediationPassword=case(PasswordRequiredIsSet=0, "Disable Automatic Logon")
|  eval remediationSSH=case(RemoteLoginIsSet=1, "Disable Remote Logon")
|  eval remediationSIP=case(SIPIsEnabled=0, "System Integrity Protection is disabled")
|  eval remediationStealth=case(StealthModeIsSet=0, "Enable Stealth Mode")
|  eval macosRemediations=mvappend(remediationAnalytic, remediationFirewall, remediationUpdate, remediationFalcon, remediationGatekeeper, remediationInternet, remediationPassword, remediationSSH, remediationSIP, remediationStealth)
| lookup local=true aid_master aid OUTPUT HostHiddenStatus, ComputerName, SystemManufacturer, SystemProductName, Version, Timezone, AgentVersion
| search HostHiddenStatus=Visible
| table aid, ComputerName, SystemManufacturer, SystemProductName, Version, Timezone, AgentVersion, macosRemediations 
| sort +ComputerName
| rename aid as "Falcon Agent ID", ComputerName as "Endpoint", SystemManufacturer as "System Maker", SystemProductName as "Product Name", Version as "OS", AgentVersion as "Falcon Version", macosRemediations as "Configuration Issues"
```

## Hunting UserLogon Events

```
event_simpleName=UserLogon
| where isnotnull(PasswordLastSet_decimal)
| where LogonDomain=ComputerName
| stats dc(UserSid_readable) as distinctSID values(UserSid_readable) as userSIDs dc(UserName) as distinctUserNames values(UserName) as userNames count(aid) as totalLogins dc(aid) as distinctEndpoints by PasswordLastSet_decimal, event_platform
| sort - distinctEndpoints
| convert ctime(PasswordLastSet_decimal) 
| where distinctEndpoints > 1
```

# Hunting Linux
## The same remote IP address having more than one failed login attempt

```
event_platform=Lin event_simpleName IN (UserLogon, UserLogonFailed2) LogonType_decimal=10
| search NOT RemoteAddressIP4 IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)
| iplocation RemoteAddressIP4
| stats count(aid) as loginAttempts, dc(aid) as totalSystemsTargeted, values(ComputerName) as computersTargeted by UserName, RemoteAddressIP4, Country, Region, City
| sort - loginAttempts
```

## The same remote IP address having more than one failed login attempt against the same username

```
event_platform=Lin event_simpleName IN (UserLogon, UserLogonFailed2) LogonType_decimal=10
| search NOT RemoteAddressIP4 IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)
| iplocation RemoteAddressIP4
| stats count(aid) as loginAttempts, dc(aid) as totalSystemsTargeted, values(ComputerName) as computersTargeted by UserName, RemoteAddressIP4, Country, Region, City
| sort - loginAttempts
```

## The same username against a single or multiple systems the point of interest

```
event_platform=Lin event_simpleName IN (UserLogon, UserLogonFailed2) LogonType_decimal=10
| search NOT RemoteAddressIP4 IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)
| iplocation RemoteAddressIP4
| stats count(aid) as loginAttempts, dc(aid) as totalSystemsTargeted, dc(RemoteAddressIP4) as remoteIPsInvolved, values(Country) as countriesInvolved, values(ComputerName) as computersTargeted by UserName
| sort - loginAttempts
```

## Successful Audit Login

```
event_platform=Lin event_simpleName IN (UserLogon) 
| iplocation RemoteAddressIP4
| convert ctime(LogonTime_decimal) as LogonTime, ctime(PasswordLastSet_decimal) as PasswordLastSet
| eval LogonType=case(LogonType_decimal=2, "Interactive", LogonType_decimal=10, "Remote Interactive/SSH")
| eval UserIsAdmin=case(UserIsAdmin_decimal=1, "Admin", UserIsAdmin_decimal=0, "Non-Admin")
| fillnull value="-" RemoteAddressIP4, Country, Region, City
| table aid, ComputerName, UserName, UID_decimal, PasswordLastSet, UserIsAdmin, LogonType, LogonTime, RemoteAddressIP4, Country, Region, City 
| sort 0 +ComputerName, LogonTime
| rename aid as "Agent ID", ComputerName as "Endpoint", UserName as "User", UID_decimal as "User ID", PasswordLastSet as "Password Last Set", UserIsAdmin as "Admin?", LogonType as "Logon Type", LogonTime as "Logon Time", RemoteAddressIP4 as "Remote IP", Country as "GeoIP Country", City as "GeoIP City", Region as "GeoIP Region"
```

## Hunting Linux RFM

```
earliest=-26h event_platform=Lin event_simpleName IN (ConfigStateUpdate, SensorHeartbeat, OsVersionInfo)
| stats latest(ConfigStateData) as ConfigStateData, latest(SensorStateBitMap_decimal) as SensorStateBitMap_decimal, latest(OSVersionString) as OSVersionString by cid, aid
| rex field=OSVersionString "Linux\\s\\S+\\s(?<kernelVersion>\\S+)?\\s.*"
| eval ConfigStateData=split(ConfigStateData, ",")
| eval userModeEnabled=if(match(ConfigStateData,"1400000000c4"),"Yes","No")
| eval rfmFlag=if(match(SensorStateBitMap_decimal,"2"),"Yes","No")
| eval sensorState=case(
userModeEnabled == "Yes" AND rfmFlag == "Yes", "User Mode Enabled",
userModeEnabled == "No" AND rfmFlag == "No",  "Kernel Mode Enabled",
userModeEnabled == "No" AND rfmFlag == "Yes", "RFM",
true(),"-")
| lookup local=true aid_master.csv aid OUTPUT ComputerName, AgentVersion as falconVersion, Version as osVersion, FirstSeen, Time as LastSeen
| fillnull kernelVersion value="-"
| table aid, ComputerName, falconVersion, osVersion, kernelVersion, sensorState, osVersion, FirstSeen, LastSeen
| convert ctime(FirstSeen) ctime(LastSeen)
| sort + ComputerName
```

## Discover RFM State

```
event_simpleName=OsVersionInfo event_platform=*
| stats latest(timestamp) AS lastTimestamp, latest(aip) as lastExtIP, latest(RFMState_decimal) as RFMState by aid
| where RFMState=1
| eval lastTimestamp=lastTimestamp/1000
| convert ctime(lastTimestamp)
| lookup aid_master aid OUTPUT Version, ComputerName as Hostname, MachineDomain, OU, SiteName
```

## UserPassword Greater than 90days by UserLogon

```
event_simpleName=UserLogon
| where isnotnull(PasswordLastSet_decimal)
| fields, aid, event_platform, ComputerName, LocalAddressIP4, LogonDomain, LogonServer, LogonTime_decimal, LogonType_decimal, PasswordLastSet_decimal, ProductType, UserIsAdmin_decimal, UserName, UserSid_readable
| eval LogonType=case(LogonType_decimal="2", "Interactive", LogonType_decimal="3", "Network", LogonType_decimal="4", "Batch", LogonType_decimal="5", "Service", LogonType_decimal="6", "Proxy", LogonType_decimal="7", "Unlock", LogonType_decimal="8", "Network Cleartext", LogonType_decimal="9", "New Credentials", LogonType_decimal="10", "RDP", LogonType_decimal="11", "Cached Credentials", LogonType_decimal="12", "Auditing", LogonType_decimal="13", "Unlock Workstation")
| eval Product=case(ProductType = "1","Workstation", ProductType = "2","Domain Controller", ProductType = "3","Server") 
| eval UserIsAdmin=case(UserIsAdmin_decimal = "1","Admin", UserIsAdmin_decimal = "0","Standard")
| eval passwordAge=now()-PasswordLastSet_decimal
| eval passwordAge=round(passwordAge/60/60/24,0)
| stats values(event_platform) as Platform latest(passwordAge) as passwordAge values(UserIsAdmin) as adminStatus by UserName, UserSid_readable
| sort - passwordAge
| where passwordAge > 90
```

## Hunting Known Commands 

```
event_platform=win event_simpleName=ProcessRollup2 FileName IN (whoami.exe, arp.exe, cmd.exe, net.exe, net1.exe, ipconfig.exe, route.exe, netstat.exe, nslookup.exe) AND NOT ParentBaseFileName IN (cmd.exe)
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| where fnameCount > 2
| eval timeDelta=lastRun-firstRun
| where timeDelta < 600
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| lookup cid_name cid OUTPUT name as Company 
| table aid, Company, ComputerName, ParentBaseFileName, filesRun, cmdsRun, timeDelta, graphExplorer
```