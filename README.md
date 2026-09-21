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
Gather Victim Network Info / External Remote Services

Scenario/Objective Context:

There is a cached copy of an internal support reference sitting in a public document cache. It names a machine that accepts remote support connections and gives the address you would reach it on from outside.

Give me the address an attacker would have targeted. Format: IP address, the public one, not the internal one

Investigation

We are handed a evidence file to begin our investigation which contains various artifacts. Upon searching the file we locate the IP address in Question.


### Answer:  Public Address	135.237.163.62

<img width="971" height="594" alt="image" src="https://github.com/user-attachments/assets/cd39bd09-1706-418c-b9af-78bf7d362315" />



---


### 🚩 Flag 2: The Guessing Source

MITRE Techniques: T1110.001
Brute Force: Password Guessing

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




### Answer:  116.45.242.115





---


### 🚩 Flag 3: How They Came In

MITRE Techniques: T1021.001
Remote Services: Remote Desktop Protocol


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



## Answer : Remote Interactive




---



### 🚩Flag 4: The Second Source
MITRE Technique:
🔸 T1059 – Command and Scripting Interpreter

Scenario Context:
The attacker used a command line to launch the binary. Understanding how it was executed may reveal intent, obfuscation, or further payloads.


Objective:
Provide the full command line used to launch the binary from Flag 3.

## KQL Used

```kusto
DeviceProcessEvents
| where DeviceName contains "flare"
| where FileName == "msupdate.exe"
| project Timestamp, FileName, ProcessCommandLine
```

## 🚩 Flag 5: Persistence Mechanism Created
MITRE Technique:
🔸 T1053.005 – Scheduled Task/Job: Scheduled Task

Scenario Context:

The attacker established persistence on the system to maintain access. In this case, they created a scheduled task to ensure their payload would execute even after reboot or logoff.

Objective:

Identify the name of the scheduled task created by the attacker.

## Investigation

To identify how the attacker maintained persistence, I reviewed scheduled task creation activity using both process execution and Defender device events.

## KQL Used

```kusto
DeviceProcessEvents
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where Timestamp between (datetime(2025-09-12) .. datetime(2025-09-30))
| where FileName in~ ("schtasks.exe", "powershell.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

### Refined Query

```kusto
DeviceEvents
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-12) .. datetime(2025-09-30))
| where ActionType == "ScheduledTaskCreated"
| extend RawTaskName = tostring(parse_json(AdditionalFields).TaskName)
| extend CleanTaskName = parse_path(RawTaskName).Filename
| project Timestamp, ActionType, CleanTaskName
| sort by Timestamp asc
```
To look for the exact scheduled task name I used the following KQL that coincided with the the previous executed command line on September 16th at 3:39 PM—right around the exact time they first broke in via RDP and ran that fake msupdate.exe binary.

## Finding

The investigation confirmed that the attacker created a scheduled task named **MicrosoftUpdateSync** to establish persistence. This ensured the malicious payload would execute automatically after system reboots or user logons, allowing the attacker to maintain long-term access to the compromised host.

<img width="975" height="407" alt="image" src="https://github.com/user-attachments/assets/09264b42-f00f-4c77-b22d-075355a28a22" />

<img width="578" height="142" alt="image" src="https://github.com/user-attachments/assets/62a7eb85-a982-4cf9-a615-8afeb6167aad" />


---
## 🚩 Flag 6: What Defender Setting Was Modified?
MITRE Technique:
🔸 T1562.001 – Impair Defenses: Disable or Modify Windows Defender

Scenario Context:
After persistence was established, the attacker altered Microsoft Defender's configuration to evade detection. Specifically, they added a folder exclusion in Defender's registry, preventing scans of certain files or directories.


Objective:
Identify the folder path that was excluded from Defender scans.

## Investigation

After identifying the attacker's persistence mechanism, I investigated whether any Microsoft Defender settings had been modified to evade detection. I reviewed Defender-related events for exclusion paths added through PowerShell or registry modifications.

## KQL Used

```kusto
DeviceEvents
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-12) .. datetime(2025-09-30))
| where InitiatingProcessCommandLine has "ExclusionPath"
    or AdditionalFields has "ExclusionPath"
| project Timestamp, InitiatingProcessCommandLine, AdditionalFields
| sort by Timestamp asc
```

## Finding

The investigation confirmed that the attacker added **C:\Windows\Temp** to Microsoft Defender's exclusion list. By excluding this directory from Defender scans, the attacker reduced the likelihood that malicious payloads stored in this location would be detected.

<img width="975" height="332" alt="image" src="https://github.com/user-attachments/assets/929459bb-2114-45b7-aec3-358fce219598" />

<img width="589" height="158" alt="image" src="https://github.com/user-attachments/assets/ff6104a8-3bf6-4608-8aa4-7d0083935842" />


---

# 🚩 Flag 7 – Discovery Command Executed
**MITRE ATT&CK:** T1082 – System Information Discovery

## Investigation

To determine how the attacker performed host reconnaissance, I reviewed process execution events for common Windows discovery commands. The initial query returned a large volume of results, so I refined the search to include known enumeration commands frequently used during post-exploitation.

## KQL Used

```kusto
DeviceProcessEvents
| where DeviceName contains "slflare"
| where Timestamp between (datetime(2025-09-25) .. datetime(2025-09-30))
| sort by Timestamp asc
```

### Refined Query

```kusto
DeviceProcessEvents
| where DeviceName contains "slflare"
| where Timestamp between (datetime(2025-09-25) .. datetime(2025-09-30))
| where ProcessCommandLine has_any (
    "systeminfo",
    "whoami",
    "hostname",
    "net ",
    "net1",
    "ipconfig",
    "netstat",
    "nltest"
)
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp asc
```

## Finding

The earliest discovery command executed by the attacker was:

<img width="975" height="471" alt="image" src="https://github.com/user-attachments/assets/d287e8bf-76c0-4263-a8da-4fbbb1fbc53b" />

This command gathers detailed information about the operating system, hardware, installed updates, and system configuration. It is commonly used by attackers during the reconnaissance phase to better understand the compromised environment. "cmd.exe" /c systeminfo is a textbook discovery command. Attackers frequently use that exact syntax to spawn a quick command shell, dump the entire system's profile (OS version, hotfixes, architecture), and exit.

<img width="577" height="156" alt="image" src="https://github.com/user-attachments/assets/a3704ebb-11c9-4046-a28f-bd10355ab558" />


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
