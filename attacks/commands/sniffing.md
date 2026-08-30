# Passive Traffic Sniffing — Commands

Commands used in Chapter 6.1 of the thesis for passive analysis of OT network traffic
(S7comm and Modbus TCP) without active interaction with devices.

---

## tcpdump — capture to file

```bash
# Capture all traffic on OT network segment
tcpdump -i eth0 -w capture_all.pcap

# Capture Modbus TCP only (port 502)
tcpdump -i eth0 -n tcp port 502 -w capture_modbus.pcap

# Capture S7comm only (port 102)
tcpdump -i eth0 -n tcp port 102 -w capture_s7comm.pcap

# Capture both industrial protocols
tcpdump -i eth0 -n 'tcp port 502 or tcp port 102' -w capture_ot.pcap

# With timestamp and verbose output (terminal)
tcpdump -i eth0 -n -tttt 'tcp port 502 or tcp port 102'
```

---

## Wireshark — display filters for industrial protocols

```wireshark
# Modbus TCP traffic
modbus

# S7comm traffic (requires Industrial Protocol dissectors)
s7comm

# Both protocols
modbus or s7comm

# Modbus Write Multiple Registers (FC 16)
modbus.func_code == 16

# Modbus Read Holding Registers (FC 3)
modbus.func_code == 3

# S7comm Job PDUs only
s7comm.param.func == 0x05

# Filter by PLC IP
ip.addr == 192.168.0.50
```

---

## What is visible without any credentials

From passive sniffing of unencrypted Modbus TCP and S7comm traffic:

| Observable | Protocol | Risk |
|---|---|---|
| Register addresses and values (read/write) | Modbus TCP | Process state fully exposed |
| PLC CPU status and operating mode | S7comm | Operational intelligence |
| Communication timing and cycle patterns | Both | Enables Replay attack preparation |
| IP and MAC addresses of all OT devices | ARP/IP | Network mapping without active scan |
| Full session content without authentication | Both | No credentials required |

---

> **Disclaimer**: For use in isolated lab environments only.
