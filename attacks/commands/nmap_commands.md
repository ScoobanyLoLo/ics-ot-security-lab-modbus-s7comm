# Nmap — Port Scanning Commands

Commands used in Chapter 6.2 of the thesis for port scanning of the OT test environment.

---

## Target addressing

| Device | IP |
|---|---|
| PLC S7-1200 | 192.168.0.50 |
| ModRSsim2 | 192.168.0.10 |
| WinCC host | 192.168.0.20 |

---

## SYN scan — standard port range

```bash
# SYN scan, ports 1-1024, default timing
nmap -sS -p 1-1024 192.168.0.50

# SYN scan — industrial-specific ports only
nmap -sS -p 102,502,443,80,161,20000,44818 192.168.0.50
nmap -sS -p 102,502,443,80,161,20000,44818 192.168.0.10
```

---

## TCP Connect scan

```bash
# Full TCP handshake scan — louder, more detectable
nmap -sT 192.168.0.50
nmap -sT 192.168.0.10

# With timing variation — aggressive (generates burst traffic)
nmap -sT -T5 192.168.0.50

# With timing variation — stealth (slow, low-profile)
nmap -sT -T1 192.168.0.50
```

---

## Service and version detection

```bash
# Identify services on open ports
nmap -sV -p 102,502 192.168.0.50

# OS detection (requires root)
nmap -O 192.168.0.50
```

---

## Observation

- SYN scan with default timing → detected by Suricata (ET SCAN NMAP signature) and Zeek
  (multiple REJ/RSTR connection states triggering rule 100904)
- T1 (paranoid) timing → significantly reduced detection rate in the test environment
- Port 102 (S7comm) and 502 (Modbus TCP) open on PLC and ModRSsim2 respectively

---

> **Disclaimer**: For use in isolated lab environments only.
