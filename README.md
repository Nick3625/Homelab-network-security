# Home Lab difensivo — Network Security

Home lab **blue team / SOC** costruito su VMware per esercitare rilevamento e
risposta agli attacchi di rete: rete segmentata (LAN / DMZ / ATTACK) con
**OPNsense** come firewall, **Suricata** come IDS e **Wazuh** come SIEM.

Progetto di preparazione a un tirocinio in sicurezza delle reti.

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
| 01 | [Brute force SSH](writeups/01-bruteforce-ssh.md) | T1110 | 🔄 In chiusura |
| 02 | [Ricognizione Nmap](writeups/02-recon-nmap.md) | T1046, T1595 | 🔄 In chiusura |
| 03 | Attacchi web su Juice Shop (SQLi, XSS, enum) | T1190 | ⏳ Da fare |
| 04 | Movimento laterale DMZ→LAN | T1021 | ⏳ Da fare |
| 05 | SYN flood | T1498 | ⏳ Da fare |
| 06 | Esfiltrazione DNS | T1048 | ⏳ Da fare |

Ogni write-up documenta: comando eseguito, alert generati (rule ID), cosa **non**
è stato rilevato, tecnica MITRE ATT&CK e raccomandazioni difensive.

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

OPNsense · Suricata (ET Open) · Wazuh · VMware Workstation · Kali Linux ·
Docker (OWASP Juice Shop)
