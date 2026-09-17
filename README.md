<img width="1536" height="1024" alt="PWD Spray" src="https://github.com/user-attachments/assets/17e95697-c640-4bfc-a3e1-82e9f670bd52" />


# Pwd-Spray-to-Full-Compromise

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Incident Response Scenario - where DeviceName contains "flare" Incident Date 14-September-2025
Suspicious activity has been detected on one of our cloud virtual machines. As a Security Analyst, you’ve been assigned to investigate this incident and determine the scope and impact of the breach.

This is an active investigation. Your objective is to reconstruct the attack timeline, identify key indicators, and answer targeted questions related to the compromise.

---
🚩 Flag 1: Attacker IP Address
MITRE Technique:
🔸 T1110.001 – Brute Force: Password Guessing

Scenario Context:

Suspicious RDP login activity has been detected on a cloud-hosted Windows server. Multiple failed attempts were followed by a successful login, suggesting brute-force or password spraying behaviour.

Objective:

Identify the external IP address that successfully logged in via RDP after a series of failures.

Investigation

I began by reviewing authentication events on the compromised endpoint to identify failed and successful Remote Desktop (RDP) logons during the incident timeframe. After observing numerous failed attempts, I refined the query to display successful logons originating from external IP addresses.

### KQL Used

```kusto
DeviceLogonEvents
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-12) .. datetime(2025-09-30))
| where isnotempty(RemoteIP)
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| project Timestamp, DeviceName, ActionType, LogonType, RemoteIP, AccountName, RemoteDeviceName
| sort by Timestamp asc
```
The investigation identified the external IP address that successfully authenticated after multiple failed login attempts, confirming a brute-force attack against the endpoint.

<img width="862" height="691" alt="image" src="https://github.com/user-attachments/assets/9fc64d0a-369f-4f8c-9397-e5c3591fc0a3" />

What is the earliest external IP address successfully logged in via RDP after multiple failed login attempts?
*

Answer 

<img width="975" height="276" alt="image" src="https://github.com/user-attachments/assets/82ca0d8c-36ea-4a06-b89d-a94b8db1107c" />



---


### 🚩 Flag 2: Compromised Account
MITRE Technique:
🔸 T1078 – Valid Accounts

Scenario Context:

The attacker gained access to the system using valid credentials through RDP. Identifying which account was accessed is critical to understanding what level of control they have.


Objective:

Determine the username that was used during the successful RDP login associated with the attacker’s IP.

Using the successful RDP logon identified in Flag 1, I pivoted to determine which account was used during the authentication event.

### KQL Used

```kusto
DeviceLogonEvents
| where DeviceName contains "flare"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP, LogonType, ActionType
```

<img width="975" height="380" alt="image" src="https://github.com/user-attachments/assets/0689cde2-9f5f-44b1-810f-d0bf05de633f" />

<img width="975" height="247" alt="image" src="https://github.com/user-attachments/assets/ab89e2f8-e518-4efa-ac9c-4c7d94b93516" />






---


### 🚩 Flag 3: Executed Binary Name
MITRE Techniques:
🔸 T1059.003 – Command and Scripting Interpreter: Windows Command Shell
🔸 T1204.002 – User Execution: Malicious File

Scenario Context:
After gaining RDP access, the attacker executed a suspicious binary on the host. Identifying this file is critical to understanding the payload or initial action and objectives of the attacker.


Objective:
Identify the name of the binary executed by the attacker.

## Investigation

To identify the attacker's payload, I reviewed process execution events associated with the compromised account. I initially examined all processes before narrowing the search to executables launched from uncommon directories such as **Public**, **Temp**, and **Downloads**.

```kusto
DeviceProcessEvents
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where Timestamp between (datetime(2025-09-16) .. datetime(2025-09-30))
| project Timestamp, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```

### Refined Query

```kusto
DeviceProcessEvents
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where Timestamp >= datetime(2025-09-16T18:43:46Z)
| where FolderPath has_any ("public", "temp", "downloads")
| project Timestamp, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```

## Finding

The investigation identified **msupdate.exe** executing from **C:\Users\Public**.

Several indicators confirmed this was a malicious executable:

- Executed from an unusual directory rather than a legitimate Windows system path.
- Used the name **msupdate.exe** to masquerade as a Microsoft Update component.
- Launched PowerShell while bypassing execution policy restrictions.



<img width="975" height="187" alt="image" src="https://github.com/user-attachments/assets/7945bc6e-bad4-4a53-a203-d35aed2e25a1" />


<img width="620" height="140" alt="image" src="https://github.com/user-attachments/assets/1f89bd9e-49c3-46d6-9bfd-6672695bce27" />


---



### 🚩Flag 4: Command Line Used to Execute the Binary
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
