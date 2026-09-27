#!/bin/sh
#
# lab_watchdog.sh - Home lab resilience watchdog per OPNsense
#
# Scopo: rendere persistente il funzionamento del lab dopo i riavvii.
#   1) Se Suricata non e' realmente in esecuzione (processo vero, non pidfile
#      stale), forza un restart pulito via configctl.
#   2) Riallinea i permessi di /var/log/suricata/eve.json in modo che
#      l'agent Wazuh (utente 'wazuh') possa leggerlo, dato che Suricata
#      ricrea il file come root:wheel -rw------- a ogni restart/rotazione.
#
# Va eseguito periodicamente via cron (vedi docs/post-reboot-persistence.md).
# Shell: /bin/sh (POSIX) - NON csh. Su OPNsense csh e' solo la shell interattiva.

LOGTAG="lab_watchdog"
EVE="/var/log/suricata/eve.json"
SURI_DIR="/var/log/suricata"

# --- 1. Suricata: e' vivo il processo? (ps e' la fonte affidabile, non la GUI)
if ! pgrep -x suricata >/dev/null 2>&1; then
    /usr/local/sbin/configctl ids restart >/dev/null 2>&1
    logger -t "$LOGTAG" "Suricata non in esecuzione -> eseguito 'configctl ids restart'"
else
    logger -t "$LOGTAG" "Suricata attivo, nessuna azione"
fi

# --- 2. eve.json leggibile dall'agent Wazuh
if [ -d "$SURI_DIR" ]; then
    chmod 755 "$SURI_DIR" 2>/dev/null
fi
if [ -f "$EVE" ]; then
    chmod 644 "$EVE" 2>/dev/null
    logger -t "$LOGTAG" "Permessi eve.json riallineati (644)"
fi

exit 0
