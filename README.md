# Home Lab difensivo — Network Security

Home lab **blue team / SOC** costruito su VMware per esercitare rilevamento e
risposta agli attacchi di rete. Rete segmentata (LAN / DMZ / ATTACK) con
**OPNsense** come firewall, **Suricata** come IDS e **Wazuh** come SIEM.


## Architettura

Rete segmentata su OPNsense con tre zone e uno stack di detection completo
(IDS → SIEM). Dettagli in [`docs/architecture.md`](docs/architecture.md).

```
Kali (ATTACK) ──▶ OPNsense (Suricata IDS) ──▶ DMZ (Juice Shop)
                        │
                        ▼
                   Wazuh SIEM (LAN)  ◀── agent su DMZ, LAN e OPNsense
```

## Scenari di attacco / detection

| # | Scenario | Tecnica MITRE | Stato |
|---|---|---|---|
| 01 | [Brute force SSH](writeups/01-bruteforce-ssh.md) | T1110 |
| 02 | [Ricognizione Nmap](writeups/02-recon-nmap.md) | T1046, T1595 |
| 03 | [Attacchi web su Juice Shop (SQLi, XSS, enum)](writeups/03-web-juiceshop.md) | T1190 |
| 04 | [Movimento laterale DMZ→LAN](writeups/04-lateral-movement.md) | T1021 |
| 05 | [Esfiltrazione DNS](writeups/06-dns-exfil.md) | T1048.003/T1071.004 |

Ogni write-up documenta: comandi eseguiti, alert generati (OPNsense e Wazuh), cosa non
è stato rilevato, tecnica MITRE ATT&CK e analisi difensive.

## Struttura del repo

```
├── README.md                        indice del progetto
├── docs/
│   ├── architecture.md              rete, VM, IP, stack
│   └── post-reboot-persistence.md   resilienza del lab ai riavvii
├── writeups/                        un write-up per scenario
├── scripts/                         automazioni (watchdog, ...)
└── assets/                          screenshot a supporto dei write-up
```

## Stack tecnologico

- OPNsense
- Suricata (ET Open)
- Wazuh
- VMware Workstation
- Kali Linux
- Docker (OWASP Juice Shop)
- Hydra, Nmap e Gobuster
- Python/Scapy
