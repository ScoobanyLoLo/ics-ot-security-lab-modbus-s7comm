# OT Network Attack Simulation & Detection Lab

> Master's thesis — *Analysis of Industrial System Vulnerability to Cyber-Attacks. Detection and Countermeasure Methods*  
> Karol Kiel · Silesian University of Technology · Faculty of Mining, Safety Engineering and Industrial Automation  
> Specialisation: Cybersecurity of Industrial Systems · May 2026

---

## Overview

This repository contains the practical artefacts from a master's thesis focused on **OT/ICS network security**: attack simulation against a real PLC-based lab environment, and detection using an open-source SIEM stack.

The work covers the full offensive–defensive cycle:

- Design and configuration of a physical/logical OT test network
- Execution of selected Layer 2–7 network attacks against Siemens S7-1200 and a Modbus TCP slave
- Detection of those attacks using **Zeek**, **Suricata**, and **Wazuh SIEM**
- Network segmentation and DMZ simulation as countermeasures
- Quantitative resistance assessment of the configured system

---

## Lab Environment

| Component | Role | Details |
|---|---|---|
| Siemens S7-1200 (CPU 1214C) | PLC / OT device | S7comm (TCP/102), Modbus TCP (502) |
| WinCC (TIA Portal) | SCADA / HMI | Visualisation, alarming |
| ModRSsim2 | Modbus TCP slave emulator | Simulated field device |
| Cisco switch | Network infrastructure | VLAN segmentation, ACLs, port security |
| Kali Linux | Attacker node | Ettercap, Scapy, Nmap, hping3 |
| Ubuntu (Wazuh SIEM host) | Detection / SIEM | Zeek + Suricata + Wazuh |

### Network topology

Two switch configurations were tested:

- **Config 1 — flat network**: all devices on a single VLAN, no segmentation. Baseline for attack surface assessment.
- **Config 2 — segmented network**: VLAN-based OT/IT separation, ACLs, protected ports. Countermeasure configuration.

IP addressing:

| Device | IP | MAC |
|---|---|---|
| PLC S7-1200 | 192.168.0.50 | 8c:f3:19:a7:33:45 |
| ModRSsim2 | 192.168.0.10 | 00:e0:4c:34:29:68 |
| WinCC host | 192.168.0.20 | — |
| Kali (attacker) | 192.168.0.100 | — |
| Wazuh SIEM | 192.168.0.200 | — |

---

## Attacks Simulated

| # | Attack | Protocol targeted | Layer | Tool |
|---|---|---|---|---|
| 1 | Passive traffic sniffing | S7comm, Modbus TCP | L2–L7 | Wireshark, tcpdump |
| 2 | Port scanning (SYN, TCP) | TCP | L4 | Nmap |
| 3 | Man-in-the-Middle (ARP poisoning) | ARP | L2 | Ettercap |
| 4 | Tampering (data modification in-flight) | Modbus TCP, S7comm | L7 | Ettercap filters |
| 5 | Replay attack | Modbus TCP | L7 | Python / pymodbus |
| 6 | Unauthorized PLC diagnostic session | S7comm (ISO-on-TCP) | L7 | snap7 / C |
| 7 | Denial of Service | TCP/102, TCP/502 | L4 | hping3 |
| 8 | Network segmentation impact analysis | — | L2–L3 | Config comparison |

---

## Repository Structure

```
├── attacks/
│   ├── replay_modbus.py          # Attachment 1 — Modbus TCP Replay attack (pymodbus)
│   └── s7client.c                # Attachment 2 — Unauthorized S7comm diagnostic session (snap7)
│
├── detection/
│   ├── zeek/
│   │   ├── arp-log.zeek          # Attachment 3 — ARP change logging stream
│   │   ├── mitm-arp-detect.zeek  # Attachment 4 — ARP MiTM detection (IP-MAC mapping)
│   │   └── ot-modbus-notice.zeek # Attachment 5 — Modbus Tampering & Replay detection
│   │
│   └── wazuh/
│       ├── decoders.xml          # Attachment 6 — JSON decoders for Zeek + Suricata logs
│       ├── rules-zeek.xml        # Attachment 7 — Wazuh alerting rules for Zeek (MITRE mapped)
│       └── rules-suricata.xml    # Attachment 8 — Wazuh alerting rules for Suricata (MITRE mapped)
│
└── README.md
```

---

## Detection Stack

### Zeek (network traffic analysis)

Three custom Zeek scripts were developed:

**`arp-log.zeek`** — logs all ARP request/reply events into a dedicated `arp.log` stream (source MAC, destination MAC, sender/target IP and hardware addresses). Provides the baseline data needed by the MiTM detector.

**`mitm-arp-detect.zeek`** — detects ARP-based MiTM attacks by tracking IP→MAC mappings for a defined set of protected OT device IPs (`192.168.0.10`, `192.168.0.20`, `192.168.0.50`). Raises `NOTICE::ARP_IP_MAC_Changed` when a mapping changes and `NOTICE::ARP_MAC_Claims_Multiple_IPs` when a single MAC claims more than 3 IPs.

**`ot-modbus-notice.zeek`** — detects Modbus TCP Tampering and Replay attacks at the application layer, correlating Modbus transaction IDs, register addresses, and source/destination pairs with ARP MiTM state.

### Suricata (signature-based IDS)

Custom Suricata rules cover:

- Port scan detection (NMAP signatures)
- DoS detection on TCP/102 (S7comm) and TCP/502 (Modbus TCP)
- Unauthorized Modbus read/write requests (source-IP whitelist)
- MiTM detection via MAC address anomaly (IP–MAC binding)
- Modbus Tampering correlation with MiTM state

### Wazuh SIEM

Custom JSON decoders parse both Zeek and Suricata log formats. Alerting rules are mapped to **MITRE ATT&CK for ICS**:

| MITRE ID | Technique | Detected by |
|---|---|---|
| T1046 | Network Service Discovery (port scan) | Zeek (100904), Suricata (200200) |
| T1499.004 | Application Exhaustion Flood (DoS) | Zeek (100953, 100992), Suricata (200250, 200500) |
| T1557 / T1557.002 | AiTM / MiTM | Zeek (110200), Suricata (201200, 201300) |
| T1565.002 | Transmitted Data Manipulation (Tampering) | Zeek (110300, 110400), Suricata (201000, 201100) |
| T1565.002 | Replay Attack | Zeek (130100), Suricata (201500) |
| T1082 | System Information Discovery (PLC diag) | Zeek (120201), Suricata (200700) |

---

## Key Findings

1. **Modbus TCP and S7comm lack authentication and encryption** — both protocols allow unauthenticated reads, writes, and session establishment by any host on the local network.

2. **Tampering and Replay were the highest-impact attacks** — data manipulation was transparent to the SCADA visualisation layer (WinCC showed no errors while values were being altered in transit).

3. **Passive sniffing provided full protocol visibility** — unencrypted industrial traffic allowed complete reconstruction of PLC register read/write cycles without raising any alarms.

4. **DoS impact was device-dependent** — ModRSsim2 became unresponsive under SYN flood; S7-1200 handled multiple parallel sessions and remained operational.

5. **Detection effectiveness was limited for application-layer attacks** — signature-based detection (Suricata) and connection-state analysis (Zeek) successfully caught scanning and DoS; Tampering/Replay detection required purpose-built Zeek scripts correlating MiTM state with Modbus register operations.

6. **Network segmentation (VLAN + ACL) blocked external access to OT zone** but provided no protection against an attacker already inside the local OT network segment.

---

## Countermeasures Assessed

| Mechanism | Implemented | Effectiveness |
|---|---|---|
| VLAN segmentation | ✅ | Effective against lateral movement from IT to OT |
| ACLs on Cisco switch | ✅ | Blocks unauthorised cross-VLAN OT access |
| Protected ports (port security) | ✅ | Limits devices per port; mitigates MAC flooding |
| DMZ zone simulation | ✅ | Isolates OT from IT; data flows through intermediary |
| Application-layer encryption | ❌ not available | Not supported by standard Modbus TCP / S7comm |
| Mutual authentication | ❌ not available | Not supported by standard Modbus TCP / S7comm |

---

## Standards and Compliance Context

The work references and applies concepts from:

- **IEC 62443** (Industrial Automation and Control Systems Security)
- **NIS2 Directive** (EU cybersecurity requirements for critical infrastructure)
- **NIST SP 800-82** (Guide to ICS Security)
- **Purdue / ISA-95 model** (OT architecture hierarchy)
- **MITRE ATT&CK for ICS** (attack classification and detection mapping)

---

## Dependencies

### Attack scripts

```
# Replay attack (Python)
pip install pymodbus

# Unauthorized PLC session (C)
# Requires snap7 library: https://snap7.sourceforge.net/
```

### Detection stack

- [Zeek](https://zeek.org/) ≥ 6.x
- [Suricata](https://suricata.io/) ≥ 7.x
- [Wazuh](https://wazuh.com/) ≥ 4.x

---

## Disclaimer

All attacks documented in this repository were performed in an isolated laboratory environment with no connection to any production or public network. The scripts and configurations are published for educational and research purposes only. Running these tools against systems without explicit authorisation is illegal.

---
