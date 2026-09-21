<img width="1024" height="682" alt="image" src="https://github.com/user-attachments/assets/b83118a2-7084-444d-b9a5-d4e87dea9d1a" />



# Another Day, Part Two

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

You know this client. Nimbus Health, the outpatient clinic we picked apart back in March. They are back on the board, and this time the shape of the problem is different.

A nearby industrial park opened. Patient volume went up, and so did billing, HR onboarding and endpoint support. Nimbus hired across every department at once and put the new starters on the same shared workstations they already had. Growth first, access review later.

During a routine credential exposure sweep we flagged one of those new hires. His identity is sitting in public, and so is an old password of his. In the same period, authentication telemetry on one of their machines shows failed logons against that account, then a success.

What we need you to work out:

   · How the account was found and why it was worth targeting
   · Whether the credentials were actually used, and from where
   · What happened once someone was on the keyboard
   · What the account reached outside its role, and where that material went
   · Whether anything was left behind, and the honest root cause

This is an active investigation. Your objective is to reconstruct the attack timeline, identify key indicators, and answer targeted questions related to the compromise.

---
🚩 Flag 1: The Remote Support Endpoint

MITRE Techniques: T1590.005 / T1133
🔸Gather Victim Network Info / External Remote Services

Scenario/Objective Context:

There is a cached copy of an internal support reference sitting in a public document cache. It names a machine that accepts remote support connections and gives the address you would reach it on from outside.

Give me the address an attacker would have targeted. Format: IP address, the public one, not the internal one

Investigation

We are handed a evidence file to begin our investigation which contains various artifacts. Upon searching the file we locate the IP address in Question.


### Answer: 

Public Address	135.237.163.62

<img width="971" height="594" alt="image" src="https://github.com/user-attachments/assets/cd39bd09-1706-418c-b9af-78bf7d362315" />



---


### 🚩 Flag 2: The Guessing Source

MITRE Techniques: T1110.001
🔸Brute Force: Password Guessing

Scenario Context:

Here is where most people go wrong. That box is being hit constantly from the open internet, dozens of sources, thousands of failures. Almost all of it is background noise that never gets anywhere.

One source is different. It guesses against this account specifically, at low volume, and it eventually succeeds. Cut it out of the storm and give me it. Format: IP address. 

Investigation

 
I begin by searching through DeviceLogonEvents looking through device name "nh-wks-it-01" and account reed. Through our search we find a short series of logon on fails and a success by the possible attacker. 



### KQL Used

```kusto
DeviceLogonEvents 

| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31)) 
| where DeviceName startswith "nh-wks-it-01" 
| where AccountName has "reed" 
| project Timestamp, ActionType, RemoteIP, AccountName 
| sort by Timestamp asc 
```

<img width="1491" height="671" alt="image" src="https://github.com/user-attachments/assets/7acd14b7-f00d-4f87-8321-bd1b656fed67" />




### Answer

116.45.242.115





---


### 🚩 Flag 3: How They Came In

MITRE Techniques: T1021.001
🔸Remote Services: Remote Desktop Protocol


Scenario Context:
The successful logon is not somebody sitting at the desk. Give me the logon type. Format: logon type name, the descriptive name Windows gives it, not the numeric ID



## Investigation

To identify the attacker's logon type I looked through the same device logs and added to KQL to project logon types. when we look in the logs we see an RDP logon. 

```kusto
DeviceLogonEvents 
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31)) 
| where DeviceName startswith "nh-wks-it-01" 
| where AccountName has "reed" 
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName
| sort by Timestamp asc
```

<img width="1801" height="606" alt="image" src="https://github.com/user-attachments/assets/263d6f2f-52e7-4d75-9868-332df19c9c68" />



## Answer 

Remote Interactive




---



### 🚩Flag 4: The Second Source
MITRE Technique:
🔸 T1059 – Command and Scripting Interpreter

Scenario Context:
They did not stay on one address. A short while after the first successful session, the same account is used from somewhere else entirely.
Give me the second external source. Format: IP address

## Investigation
Finding How They Got In: I started by digging through DeviceLogonEvents on nh-wks-it-01 to filter out background noise and look specifically at m.reed. I saw several failed login attempts followed by a successful RemoteInteractive login over RDP from the external IP 116.45.242.115.
Tracking the IP Switch: Shortly after the initial login, I checked the logs for further activity from m.reed and noticed the connection switched to a second external IP address, 45.131.194.61, showing the attacker was still actively using the compromised account.



## KQL Used

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2026-05-29T01:20:00Z) .. datetime(2026-05-29T02:00:00Z))
| where AccountName has "reed"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP
| sort by Timestamp asc
```
<img width="2206" height="693" alt="image" src="https://github.com/user-attachments/assets/5c8689d5-516e-4032-a1db-cd6fdbf06b50" />

## Answer 

45.131.194.61



## 🚩 Flag 5: Getting Their Bearings
MITRE Technique: Discovery Command Burst
🔸 Technique: Software Discovery (T1518), System Information Discovery (T1082), Network Share Discovery (T1135), Permission Groups Discovery: Domain Groups (T1069.002)

Scenario Context:

Once they are on, there is a short burst of built-in commands while they work out where they have landed and what the account can do.

Careful with your anchor. The session opens a couple of minutes before the first real command, and what sits in between is Windows and Edge doing first-run housekeeping, not the operator.

Reconstruct the burst, in the order it ran. Format: every command in the burst, in order, comma-separated, exactly as it appears in the log including any switches


## Investigation

Filtering System Noise: When looking at DeviceProcessEvents right after the RDP session opened, I noticed several background processes like MicrosoftEdgeUpdate.exe and sihost.exe running automatically. I filtered out those system and browser events to isolate only the commands manually typed by the attacker.

Reconstructing the Command Sequence: By sorting the remaining process events by timestamp, I identified a distinct, quick burst of discovery commands run by m.reed. The attacker first checked their current identity (whoami) and host name (hostname), then looked for available file shares (net view \\NH-FS-01), and finally checked for group memberships (net group "HR" /domain

## KQL Used

```kusto
DeviceProcessEvents
| where AccountName == "m.reed"
| where TimeGenerated >= datetime(2026-05-29T01:30:00Z) and TimeGenerated <= datetime(2026-05-29T01:45:00Z)
| where FileName in~ ("whoami.exe", "HOSTNAME.EXE", "ipconfig.exe", "net.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```
<img width="2194" height="599" alt="image" src="https://github.com/user-attachments/assets/530ae0d6-ba0c-4087-8237-edb56cd81f93" />


## Answer

whoami, hostname, net view \\NH-FS-01, net group "HR" /domain

---
## 🚩 Flag 6: Looking at the File Server
MITRE Technique:
🔸 Tactic: Discovery (TA0007)
🔸 Technique: Network Share Discovery (T1135)

Scenario Context:
The recon does not stop at the local box. One command asks a specific server what it is sharing. Give me it. Format: full command, exactly as it appears in the log.


## Investigation

Identifying Share Reconnaissance: After getting local context on the machine, the attacker pivoted to finding stored network data. I queried DeviceProcessEvents for net.exe activity and found the command net view \\NH-FS-01.

Analyzing the Intent: Running net view directly against NH-FS-01 allowed the attacker to list all available SMB network shares hosted on the file server before attempting to access sensitive directories.

## KQL Used

```kusto
DeviceProcessEvents
| where AccountName == "m.reed"
| where TimeGenerated >= datetime(2026-05-29T01:30:00Z) and TimeGenerated <= datetime(2026-05-29T01:45:00Z)
| where FileName =~ "net.exe" or ProcessCommandLine has "net view"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

<img width="1861" height="557" alt="image" src="https://github.com/user-attachments/assets/230c6cf6-ebcb-432f-a6f1-f3cdd18184c2" />

## Answer

NH-FS-01

---

# 🚩 Flag 7 – Where They Put It
MITRE Technique:
🔸 Tactic: Collection (TA0009) / Command and Control (TA0011)
🔸 Technique: Data Staged: Local Data Staging (T1074.001)

Scenario Context:
They pulled material together locally before moving it. Give me the folder they staged it in. Format: full folder path, no filename


## Investigation

Locating the Staging Directory: To find where the attacker gathered files before taking them, I looked at DeviceFileEvents for file creation and modification events tied to m.reed.
Identifying Local Collection: I spotted new files being written directly into the user's standard working directory, confirming they were staging sensitive HR records locally before preparing them for exfiltration.

## KQL Used

```kusto
DeviceFileEvents
| where TimeGenerated >= datetime(2026-05-29T01:50:00Z) and TimeGenerated <= datetime(2026-05-29T02:15:00Z) 
| where RequestAccountName == "m.reed" or InitiatingProcessAccountName == "m.reed" 
| where ActionType in~ ("FileCreated", "FileModified", "FileRenamed") 
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine 
| order by TimeGenerated asc 
```

<img width="2183" height="569" alt="image" src="https://github.com/user-attachments/assets/2a83e327-2eb9-4db3-bb20-2351039b6e39" />


## Answer

C:\Users\m.reed\Documents\SupportReview


---

# 🚩 Flag 8 – Archive File Created
**MITRE ATT&CK:** T1560.001 – Archive Collected Data

## Investigation

Following the discovery phase, I searched file creation events for archive files created in common staging locations such as **Temp**, **AppData**, and **ProgramData**.

## KQL Used

```kusto
DeviceFileEvents
| where DeviceName contains "slflare"
| where Timestamp between (datetime(2025-09-15) .. datetime(2025-09-30))
| where FolderPath has_any ("Temp", "AppData", "ProgramData")
| where FileName endswith ".zip"
| project Timestamp, FolderPath, FileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

## Finding

After performing system discovery (Flag 7), the attacker created an archive file called "backup_sync.zip" at 
Sep 16, 2025 3:43:42 PM in the user's AppData Temp directory, preparing collected data for exfiltration. This was created just one minute after the discovery commands completed indicating an automated script handling the full chain from reconnaissance to data staging.

<img width="1833" height="291" alt="image" src="https://github.com/user-attachments/assets/6a6b4092-1610-4359-b6cc-d821b7eec4ea" />


<img width="599" height="135" alt="image" src="https://github.com/user-attachments/assets/3d0f39dd-c547-4196-a12c-f4cb4f03bc9f" />


---

# 🚩 Flag 9 – Command and Control (C2)
**MITRE ATT&CK:**
- T1071.001 – Application Layer Protocol: Web Protocols
- T1105 – Ingress Tool Transfer

## Investigation

To identify the attacker's command and control infrastructure, I reviewed outbound network connections initiated by the compromised endpoint. I excluded known legitimate Microsoft domains to reduce background noise and focus on suspicious external destinations.

## KQL Used

```kusto
DeviceNetworkEvents
| where DeviceName contains "slflare"
| where Timestamp between (datetime(2025-09-15) .. datetime(2025-09-17))
| where isnotempty(RemoteIP)
| where RemoteUrl !has "microsoft.com"
| where RemoteUrl !has "windows.com"
| where RemoteUrl !has "live.com"
| where RemoteUrl !has "brave.com"
| project Timestamp,
          RemoteIP,
          RemoteUrl,
          RemotePort,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| sort by Timestamp asc
```

## Finding

During the investigation of the compromised endpoint slflare, an indicator of compromise (IoC) was identified involving the execution of a malicious background script. An attacker utilized a masqueraded script named msupdate.exe to execute a local PowerShell payload (update_check.ps1), which subsequently initiated an outbound Command and Control (C2) network connection to the external IP address

<img width="975" height="293" alt="image" src="https://github.com/user-attachments/assets/c0b0a273-3aeb-40fb-bc92-679c28167b16" />


<img width="588" height="134" alt="image" src="https://github.com/user-attachments/assets/d2c10efe-23e1-4930-ae70-8c6483f113a2" />


---

# 🚩 Flag 10 – Exfiltration Attempt
**MITRE ATT&CK:** T1048.003 – Exfiltration Over Unencrypted Protocol

## Investigation

After identifying the creation of **backup_sync.zip**, I pivoted into **DeviceNetworkEvents** to examine outbound network traffic immediately following the archive creation. I correlated public network connections with the initiating process to identify any attempted data transfers.

## KQL Used

```kusto
DeviceNetworkEvents
| where DeviceName contains "slflare"
| where Timestamp between (datetime(2025-09-15) .. datetime(2025-09-30))
| where RemoteIPType == "Public"
| join kind=leftouter (
    DeviceNetworkEvents
    | where DeviceName contains "slflare"
    | where Timestamp between (datetime(2025-09-15) .. datetime(2025-09-30))
    | where RemoteIPType == "Public"
    | summarize Count=count() by RemoteIP, RemotePort
) on RemoteIP, RemotePort
| project Timestamp,
          RemoteIP,
          RemotePort,
          Count,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

## Finding

After the attacker created the staged archive file (backup_sync.zip), I reviewed DeviceNetworkEvents for outbound connections occurring immediately afterward. The investigation identified a curl command performing an HTTP POST request to upload the archive to the attacker's external server at 185.92.220.87 over port 8081. This activity confirmed an attempted data exfiltration over an unencrypted protocol, resulting in the flag value 185.92.220.87:8081.

<img width="975" height="80" alt="image" src="https://github.com/user-attachments/assets/1d3ab917-f471-4905-9221-e92cfe707818" />



This activity confirmed an attempted data exfiltration over an **unencrypted HTTP connection**, matching **MITRE ATT&CK T1048.003 – Exfiltration Over Unencrypted Protocol**.

<img width="583" height="158" alt="image" src="https://github.com/user-attachments/assets/eae9e43d-9271-48d2-834f-9d3c7a921b8a" />

---

# Attack Timeline

| Phase | Activity | MITRE ATT&CK |
|--------|----------|--------------|
| Initial Access | Successful RDP login following repeated failed authentication attempts | T1110.001 |
| Execution | `msupdate.exe` executed and launched PowerShell | T1059.003 |
| Persistence | Created **MicrosoftUpdateSync** scheduled task | T1053.005 |
| Defense Evasion | Added **C:\Windows\Temp** to Microsoft Defender exclusions | T1562.001 |
| Discovery | Executed `cmd.exe /c systeminfo` | T1082 |
| Collection | Created **backup_sync.zip** | T1560.001 |
| Command & Control | Connected to **185.92.220.87** | T1071.001 |
| Exfiltration | Uploaded archive to **185.92.220.87:8081** using `curl` | T1048.003 |

---

# Investigation Summary

Throughout this investigation, Microsoft Defender XDR Advanced Hunting was used to correlate authentication, process execution, registry modifications, file creation, and network telemetry to reconstruct the complete attack lifecycle.

The attacker gained initial access through a successful RDP brute-force attack, executed a masqueraded binary that launched a malicious PowerShell payload, established persistence through a scheduled task, modified Microsoft Defender to evade detection, performed system reconnaissance, staged collected data into an archive, communicated with an external command and control server, and ultimately attempted to exfiltrate the archive over HTTP using `curl`.

This investigation demonstrates how Defender XDR telemetry can be correlated across multiple data sources to identify attacker behavior, validate indicators of compromise, and map each phase of an intrusion to the MITRE ATT&CK framework.

---

# Lessons Learned

- Microsoft Defender XDR provides comprehensive telemetry for reconstructing attacker activity across authentication, process, registry, file, and network events.
- KQL enables efficient threat hunting by allowing analysts to pivot between related event types and progressively refine investigations.
- Mapping findings to the MITRE ATT&CK framework provides valuable context for understanding attacker objectives and techniques.
- Correlating multiple data sources is essential for identifying the complete attack chain rather than viewing isolated security events.
- Effective threat hunting requires iterative query refinement to reduce noise and focus on meaningful indicators of compromise.
