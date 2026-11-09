# Persistenza del lab dopo i riavvii

> Problema: dopo un riavvio del PC host, alcuni componenti del lab non tornano
> operativi da soli. Questo documento descrive come renderli resilienti.

## Quadro dei componenti

| Componente | Comportamento al reboot | Soluzione |
|---|---|---|
| Kea / DHCP (porta 67) | Parte male (dnsmasq rioccupa la 67) | Ricarico un backup di config a ogni avvio + disattivo dnsmasq |
| **Suricata** | Puo' non ripartire / restare "stale" | Watchdog (vedi sotto) |
| **Permessi `eve.json`** | Ricreato `root -rw-------`, Wazuh smette di leggere | Watchdog (vedi sotto) |

## Il watchdog: una soluzione per due problemi

Lo script [`scripts/lab_watchdog.sh`](../scripts/lab_watchdog.sh) copre sia Suricata sia i permessi:

1. **Suricata** — controlla con `pgrep` che il *processo reale* sia in esecuzione
   (la GUI OPNsense non e' affidabile su questo). Se manca, forza
   `configctl ids restart`. Questo copre sia il caso "giu' dopo il boot" sia il
   pidfile stale (configctl dice "running as pid X" ma `ps` non lo trova).
2. **eve.json** — rimette `chmod 644` sul file (e `755` sulla cartella) così
   l'utente `wazuh` dell'agent puo' leggerlo. Necessario perche' Suricata ricrea
   il file come `root:wheel -rw-------` a ogni restart/rotazione, impedendo così l'accesso ai log all'agent Wazuh.

### Perche' e' robusto rispetto ai reboot

Facendo un backup della configurazione del firewall, la **voce cron** che lancia il watchdog viene salvata in `config.xml`, quindi
finisce **dentro il backup** e ricaricandolo ad ogni avvio include automaticamente l'esecuzione regolare dello script.
Inoltre, girando ogni pochi minuti, il watchdog **auto-ripara** anche restart di
Suricata avvenuti in corso di sessione, non solo al boot.

## Installazione (sull'OPNsense)

Shell OPNsense = csh in interattivo, ma lo script gira con `/bin/sh`.

**1. Copia lo script e rendilo eseguibile:**
```
# copia il contenuto di scripts/lab_watchdog.sh in:
/usr/local/bin/lab_watchdog.sh
chmod +x /usr/local/bin/lab_watchdog.sh
```

**2. Registra la configd action** (necessaria perche' il cron OPNsense esegue
solo comandi registrati, non shell arbitraria):
```
# copia scripts/actions_labwatchdog.conf in:
/usr/local/opnsense/service/conf/actions.d/actions_labwatchdog.conf
service configd restart
```
> IMPORTANTE: il campo `type:script_output` e' cio' che rende l'action
> visibile nella tendina Command del Cron. Con `type:script` (senza `_output`)
> l'action funziona ma NON compare in GUI.

Verifica che l'action sia registrata prima di andare in GUI:
```
configctl labwatchdog run
```
Se esegue lo script (nessun "Action not found"), e' registrata correttamente.

**3. Aggiungi il job in cron:**
`System → Settings → Cron` → **Add** → seleziona il comando
*"lab watchdog - verifica Suricata e permessi eve.json"* → schedula ogni
**5 minuti** (`*/5`). Salva e applica.

## Verifica

```
# forza a mano una prova
/usr/local/bin/lab_watchdog.sh
# guarda i log del watchdog
clog /var/log/system/latest.log | grep lab_watchdog | tail
# conferma processo Suricata reale
pgrep -x suricata
# conferma permessi
ls -l /var/log/suricata/eve.json
```

Poi: genera traffico dalla Kali e verifica che gli alert `rule.groups:suricata`
compaiano in Wazuh.

## Note e limiti
- `chmod 644` rende `eve.json` leggibile a tutti gli utenti locali del firewall:
  può essere accettabile in un homelab, in altri ambienti potrebbe rivelarsi una gestione non sicura.
- Se dopo un aggiornamento del ruleset Suricata parte ma con regole "vecchie",
  serve comunque il ciclo manuale Enabled OFF→ON in  `Intrusion Detection → Administration` (caso raro, solo post-update).
