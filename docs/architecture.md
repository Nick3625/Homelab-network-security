# Architettura del lab

Home lab difensivo (blue team / SOC) su VMware Workstation per preparazione al
tirocinio in sicurezza delle reti.

## Ambiente

- **Host**: Windows, VMware Workstation, 16 GB RAM totali
- **Hypervisor**: VMware Workstation

## Schema di rete

```
Internet
   |
[VMnet8 NAT] ── OPNsense ── VMnet2 (LAN, 10.10.10.0/24) ── Ubuntu LAN, Wazuh (10.10.10.10)
                    |
                    ├── VMnet3 (DMZ, 10.10.20.0/24) ── Ubuntu DMZ (10.10.20.10) — Juice Shop via Docker
                    └── VMnet4 (ATTACK, 10.10.30.0/24) ── Kali Linux
```

## Interfacce OPNsense

| Interfaccia | Nome OPNsense | Rete VMware | Subnet | Gateway |
|---|---|---|---|---|
| em0 | WAN | NAT (VMnet8) | DHCP | — |
| em1 | LAN | VMnet2 | 10.10.10.0/24 | 10.10.10.1 |
| em2 | DMZ (opt1) | VMnet3 | 10.10.20.0/24 | 10.10.20.1 |
| em3 | ATTACK (opt2) | VMnet4 | 10.10.30.0/24 | 10.10.30.1 |

## Macchine virtuali

| VM | Ruolo | Rete | IP | RAM |
|---|---|---|---|---|
| OPNsense | Firewall / router / IDS (Suricata) | tutte e 4 | vedi sopra | 2 GB |
| Kali Linux | Attaccante (hydra, nmap, gobuster) | ATTACK | DHCP | 2 GB |
| Ubuntu Server | Host DMZ — Docker + Juice Shop, agent Wazuh | DMZ | 10.10.20.10 | 1 GB |
| Ubuntu Server | Host LAN, agent Wazuh | LAN | DHCP | 1 GB |
| Wazuh | SIEM (dashboard `https://10.10.10.10`) | LAN | 10.10.10.10 | 4 GB min |

## Stack difensivo

- **IDS**: Suricata (plugin `os-suricata`) su interfacce DMZ e ATTACK, ruleset ET Open.
- **SIEM**: Wazuh (OVA), agent su Ubuntu DMZ/LAN e su OPNsense (per ingest `eve.json`).
- **Persistenza**: watchdog via cron per Suricata + permessi `eve.json`
  (vedi [`post-reboot-persistence.md`](post-reboot-persistence.md)).

## Note operative importanti

- Shell OPNsense = **csh** (attenzione a redirect stile bash).
- Verificare lo stato reale dei servizi via shell (`ps aux`, `service ... status`),
  la GUI non e' sempre affidabile.
- Wazuh (OVA) richiede min. 4 GB RAM; con 2 GB va in stallo.
- Container Docker: usare sempre `--restart unless-stopped`.
- Kea DHCP: dopo reboot puo' non ripartire (porta 67 occupata) → ricarico backup
  di config + disattivo dnsmasq.
