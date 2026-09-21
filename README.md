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

MITRE Techniques: 
🔸T1590.005 / T1133
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

# 🚩 Flag 8 – How It Left
MITRE Technique:
🔸 Tactic: Exfiltration (TA0104)
🔸 Technique: Exfiltration Over Alternative Protocol: Exfiltration Over RDP Client Drive Redirection (T1048.003)

Scenario Context:
This is the beat worth understanding. Nothing was uploaded, no cloud service was touched, and nothing left over the network in a way most people would think to look for. The archive walked out through the session they were already sitting in. Follow the archive and give me the destination path it was written to. Format: full destination path as it appears in the telemetry no need for the file name.

## Investigation

Identifying Virtual Channel Exfiltration: Standard network monitoring misses file transfers executed over an active RDP virtual channel. When an attacker redirects local client drives during an RDP session, remote drives are mapped under the \\tsclient\ virtual device path.

Tracing the Destination Path: I searched DeviceFileEvents for file creation and write actions involving .zip archives where the FolderPath targeted the redirected RDP channel. The telemetry confirmed the archive support_review_202605.zip was written directly across the RDP session to the redirected path \\tsclient\G\Temp\NimbusSupport\

## KQL Used

```kusto
DeviceFileEvents
| where InitiatingProcessAccountName == "m.reed" or RequestAccountName == "m.reed"
| where TimeGenerated >= datetime(2026-05-29T01:50:00Z) and TimeGenerated <= datetime(2026-05-29T02:15:00Z) 
| where ActionType in ("FileCreated", "FileCopied", "FileModified")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath
| sort by Timestamp asc
```
<img width="2100" height="580" alt="image" src="https://github.com/user-attachments/assets/32fc66f5-9e7c-4f3a-9679-ac4054f8e917" />


## Answer
\\tsclient\G\Temp\NimbusSupport\support_review_202605.zip


---

# 🚩 Flag 9 – Where They Actually Sat
MITRE Technique:
🔸 Tactic: Discovery (TA0007) / Lateral Movement (TA0008)
🔸 Technique: Remote Services: SMB/Windows Admin Shares (T1021.002)

Scenario Context:
HR data was read, so the obvious assumption is that they got onto the file server. Check it rather than assuming it. Tell me whether this account ever ran anything on the file server, and if not, how the HR material was reached instead. Format: short phrase naming two things. First, yes or no on the file server. Second, how the files were reached.

## Investigation

Checking File Server Execution: I queried DeviceProcessEvents across the environment to verify whether m.reed ever established an interactive session or executed processes on NH-FS-01. The logs showed zero process execution by this user on the file server itself, confirming the attacker never logged in or moved laterally onto NH-FS-01.

Determining Remote Access Method: I cross-referenced DeviceFileEvents and network connections on nh-wks-it-01. The telemetry showed nh-wks-it-01 reading and copying HR files remotely across the network over standard SMB file shares (\\NH-FS-01\HR), proving the attacker remained seated on nh-wks-it-01 the entire time and accessed the server's data over network shares.

## KQL Used

```kusto
DeviceProcessEvents
| where DeviceName startswith "NH-FS-01"
| where AccountName has "reed" or InitiatingProcessAccountName has "reed"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## Answer



---

# 🚩 Flag 10 – Containment
MITRE Technique:
🔸 Tactic: Incident Response / Containment
🔸 Technique: Execution Isolation (M1040) / User Account Management (M1018)

Scenario Context:
The clinic wants to call this a curious new starter and reset his password. You have seen the evidence. What is the first containment action, and why is a password reset alone not enough? Format: the action and the reasoning.

Investigation
Evaluating Response Effectiveness: Resetting an account password prevents new authentication attempts, but it does not automatically terminate existing, authenticated sessions in an active Windows RDP connection.

Determining the Priority Action: Because the threat actor established an interactive RDP session on nh-wks-it-01 and was actively copying files over redirected channels, resetting m.reed's domain password alone would leave the live session open and operational. Immediate device network isolation is required to sever the active tunnel and cut off command execution.



## Answer

Isolate nh-wks-it-01 from the network, a password reset does not kill active RDP sessions

---

# Attack Timeline

| Phase | Activity | MITRE ATT&CK |
|--------|----------|--------------|
| Initial Access | Successful RDP login using valid credentials (m.reed) from IP 116.45.242.115 | T1078, T1021.001 |
| Execution | Command burst executed via cmd.exe (whoami, hostname, net)| 1059.003 |
| Persistence | No Persistence Established (Verified via scheduled tasks/services audit) | 
| Defense Evasion | IP address pivot during active session (45.131.194.61) | T1562 |
| Discovery | Enumerated file server shares using net view \\NH-FS-01| T1135, T1082 |
| Collection | Accessed HR files via SMB share (\\NH-FS-01\HR) and staged in C:\Users\m.reed\Documents| T1074.001 |
| Command & Control | Active RDP Virtual Channel session maintained on nh-wks-it-01 | T1219 |
| Exfiltration | Staged archive support_review_202605.zip exfiltrated via RDP drive redirection to \\tsclient\G\Temp\NimbusSupport\| T1048.003 |

---

# Investigation Summary

Throughout this investigation, Microsoft Defender XDR Advanced Hunting was used to correlate authentication events, process execution, network connections, and file system telemetry to reconstruct the complete attack lifecycle on nh-wks-it-01.

The threat actor gained initial access by leveraging compromised credentials for m.reed over RDP, pivoting IP addresses during the active session. Once connected, the operator executed a short burst of built-in Windows command-line utilities to conduct initial host and domain discovery. Without pivoting directly onto the internal file server NH-FS-01, the attacker accessed sensitive HR records remotely over standard SMB shares, staged the data inside the user's local Documents folder, and archived it into support_review_202605.zip. Finally, the archive was exfiltrated directly across the active RDP virtual channel using client drive redirection (\\tsclient), bypassing traditional network upload monitoring.

This investigation demonstrates how Defender XDR telemetry can be correlated across DeviceLogonEvents, DeviceProcessEvents, and DeviceFileEvents to uncover stealthy exfiltration channels, verify the absence of persistence mechanisms, and inform immediate containment strategies—specifically isolating the endpoint rather than relying solely on a password reset.

---

# Lessons Learned

RDP virtual channels (such as \\tsclient drive redirection) allow attackers to exfiltrate data directly through active sessions without generating standard web or cloud upload traffic.

Resetting an account password stops future authentications but does not terminate active RDP sessions; immediate host isolation is necessary to stop live exfiltration.

Cross-referencing process telemetry across hosts is vital to confirm whether an account actually logged into a remote server or simply accessed data over SMB shares.

Filtering out legitimate background processes (e.g., system updates, browser housekeeping) is essential to clearly isolate manual operator command bursts during post-compromise discovery.

Mapping each artifact to the MITRE ATT&CK framework helps structure incident write-ups cleanly for both SOC operations and portfolio documentation.
