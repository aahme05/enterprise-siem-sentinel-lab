# Enterprise SIEM Implementation & Cyber Threat Detection Lab

**CST8808 — Cyber Incident Response** · April 2025
Platform: Microsoft Azure Sentinel · Target: Windows Server 2016 (IIS) · Attacker: Kali Linux · Environment: VMware Workstation

## Overview

A cloud-native SIEM built from scratch and validated end-to-end: a Windows Server 2016 web server was onboarded to Microsoft Sentinel, instrumented with multiple log sources, and then actually attacked from a Kali Linux box to confirm the detections fire correctly — not just configured, but proven to work against real traffic.

Rather than using the originally-suggested on-prem Splunk Enterprise, this build uses **Microsoft Sentinel**, a cloud-hosted SIEM with no local server to maintain.

## Architecture

- **Windows Server 2016** — runs IIS (target web app) and Windows Firewall logging, connected to Azure via **Azure Arc** + the **Azure Monitor Agent (AMA)**
- **Kali Linux** — attacker box (Nmap, Hydra)
- **Microsoft Sentinel** — collects logs, evaluates detection rules, raises incidents

An isolated VMware network (`VMnet16`, `192.168.1.0/24`) keeps all lab traffic contained; a second NAT-mode adapter on the Windows Server provides outbound internet access to reach Azure.

## Log Pipeline

Two custom Data Collection Rules (DCRs) stream logs from the on-prem server into the Sentinel workspace:

| DCR | Source | Destination table |
|---|---|---|
| DCR-Firewall-Logs | `pfirewall.log` (Windows Firewall) | `FirewallLogs_CL` |
| DCR-IIS-Logs | IIS logs (`W3SVC1`) | Custom IIS table |
| DCR-Snort-logs | Snort `alert.ids` | `SnortIDSAlert_CL` |

The **Windows Security Events** Sentinel solution was also installed to ingest Security log events (including Event ID 4625 — failed logon) without a custom table.

## Real-Time Detection: Snort IDS

Snort 2.9.20 runs directly on the Windows Server with a custom rule set (`icmp.rules`) detecting:

- SYN scans
- XMAS scans (FIN+PSH+URG flags)
- FIN scans
- UDP scans
- TCP full-connect scans

Matches are written to `alert.ids`, forwarded to Sentinel via the Snort DCR, and picked up by dedicated Analytics Rules (one per scan type) that promote matching log entries into Sentinel Incidents.

## Detection Rule: Brute Force via Failed RDP Logons

The most involved rule detects RDP brute-forcing end-to-end:

1. Hydra hammers port 3389 with credential attempts from Kali
2. Each failure logs as **Event ID 4625** in the Windows Security log
3. AMA forwards new Security events to the `SecurityEvent` table in near real time
4. A Sentinel Analytics Rule runs every 5 minutes over the last 5 minutes of data:

```kql
SecurityEvent
| where EventID == 4625
| where TargetAccount has "administrator"
| summarize FailureCount = count() by IpAddress, bin(TimeGenerated, 1m)
| where FailureCount > 10
```

5. Exceeding the threshold (10+ failures/minute) auto-generates a **High severity** Incident

## Validation

Live attacks were launched from Kali against the Windows Server to confirm the whole pipeline, not just the config:

- `nmap -sS` / `nmap -sX` scans → correctly classified as SYN Scan / XMAS Scan incidents
- Hydra RDP brute force → correctly classified as a Brute Force Detection incident

All incidents appeared in Sentinel's Incidents queue, correctly labeled by type, confirming the DCRs, custom log tables, and Analytics Rules were wired together correctly.

## Why Sentinel Over On-Prem SIEM

- **Scalability** — cloud resources scale with log volume automatically
- **No hardware** — nothing to rack, patch, or maintain on-prem
- **Built-in threat intel** — Microsoft's global feeds and ML detections out of the box
- **Single pane of glass** — the Azure Portal covers every connected data source
- **Fast to stand up** — hours, not the days/weeks typical of on-prem SIEM rollouts

## Tools

Microsoft Azure Sentinel · Azure Arc · Azure Monitor Agent (AMA) · Snort IDS · KQL · Nmap · Hydra · VMware Workstation · Windows Server 2016 (IIS) · Kali Linux
