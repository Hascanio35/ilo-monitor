#!/usr/bin/env bash
# ============================================================
# iLO Monitor - aggiornamento dei file su un'installazione v2
# gia' migrata.
#
# Da usare quando scarichi una versione nuova dello zip sopra
# quella precedente: copia i file applicativi, riallinea schema
# e servizi, riavvia e verifica.
#
# Non tocca il database se non per la migrazione (che e'
# idempotente) e non tocca config/.env ne' config/secret.key,
# quindi i server e le loro password restano dove sono.
#
# Uso:  sudo ./update.sh
# ============================================================

set -euo pipefail

BASE="/opt/ilo-monitor"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BASE/backup-$STAMP"

say(){ printf '\n\033[1;32m==>\033[0m %s\n' "$1"; }
warn(){ printf '\033[1;33m    %s\033[0m\n' "$1"; }
die(){ printf '\n\033[1;31mERRORE:\033[0m %s\n' "$1" >&2; exit 1; }

# I servizi vengono fermati per la migrazione dello schema. Se lo
# script muore in mezzo (set -e, un errore di mysql, un Ctrl-C) devono
# ripartire comunque: senza questa rete di sicurezza si resta con la
# dashboard spenta e un 502 da nginx.
SERVIZI_FERMI=0
riavvia_servizi(){
    if [ "$SERVIZI_FERMI" -eq 1 ]; then
        printf '\n\033[1;33m    riavvio i servizi\033[0m\n'
        systemctl start ilo-monitor.service 2>/dev/null || true
        systemctl start ilo-monitor-collector.timer 2>/dev/null || true
        SERVIZI_FERMI=0
    fi
}
trap riavvia_servizi EXIT INT TERM

[ "$(id -u)" -eq 0 ] || die "Esegui lo script come root (sudo ./update.sh)"
[ -d "$BASE" ] || die "$BASE non esiste: usa prima ./upgrade.sh"
[ -f "$BASE/config/.env" ] || die "$BASE/config/.env non trovato"
[ -x "$BASE/venv/bin/python" ] || die "Ambiente virtuale non trovato in $BASE/venv"
[ -f "$SRC/app/main.py" ] || die "Lancia lo script dalla cartella dello zip scompattato"

# Se il database non e' ancora stato migrato, questo non e'
# l'aggiornamento giusto.
if [ ! -f "$BASE/app/crypto_util.py" ]; then
    die "Installazione ancora alla v1: usa ./upgrade.sh"
fi

# shellcheck disable=SC1091
set -a; . "$BASE/config/.env"; set +a
: "${DB_NAME:=ilomonitor}"
: "${DB_USER:=ilomonitor}"
: "${DB_HOST:=127.0.0.1}"
[ -n "${DB_PASSWORD:-}" ] || die "DB_PASSWORD assente in config/.env"

# ------------------------------------------------------------
say "1/7  Copia dei file attuali in $BACKUP"
# ------------------------------------------------------------
mkdir -p "$BACKUP"
cp -a "$BASE/app" "$BACKUP/app"
cp -a "$BASE/web" "$BACKUP/web"

# ------------------------------------------------------------
say "2/7  Copia dei nuovi file"
# ------------------------------------------------------------
mkdir -p "$BASE/app" "$BASE/web" "$BASE/logs" "$BASE/sql"
rm -rf "$BASE/app/__pycache__"

install -m 644 "$SRC/app/__init__.py"          "$BASE/app/__init__.py"
install -m 644 "$SRC/app/crypto_util.py"       "$BASE/app/crypto_util.py"
install -m 644 "$SRC/app/main.py"              "$BASE/app/main.py"
install -m 644 "$SRC/app/redfish_collector.py" "$BASE/app/redfish_collector.py"
install -m 644 "$SRC/app/auth.py"              "$BASE/app/auth.py"
install -m 644 "$SRC/app/alerts.py"            "$BASE/app/alerts.py"
install -m 644 "$SRC/app/mailer.py"            "$BASE/app/mailer.py"
install -m 644 "$SRC/web/index.html"           "$BASE/web/index.html"
install -m 644 "$SRC/web/login.html"           "$BASE/web/login.html"
install -m 644 "$SRC/web/manifest.webmanifest" "$BASE/web/manifest.webmanifest"
mkdir -p "$BASE/web/icons"
install -m 644 "$SRC"/web/icons/*.png          "$BASE/web/icons/"
install -m 644 "$SRC/sql/02-migrazione.sql"        "$BASE/sql/02-migrazione.sql"
install -m 755 "$SRC/bin/ilo-monitor-interval" /usr/local/bin/ilo-monitor-interval
install -m 755 "$SRC/bin/ilo-monitor-user"     /usr/local/bin/ilo-monitor-user
# Lo shebang punta all'interprete dell'ambiente virtuale: se
# l'installazione non e' in /opt/ilo-monitor lo allineiamo.
sed -i "1s|.*|#!$BASE/venv/bin/python3|" /usr/local/bin/ilo-monitor-user

# ------------------------------------------------------------
say "3/7  Allineamento dello schema del database"
# ------------------------------------------------------------
# ALTER TABLE ha bisogno del lock sulla tabella: se il collector sta
# girando resta in attesa all'infinito. Fermiamo tutto per il tempo
# della migrazione e ripartiamo subito dopo.
say "     fermo i servizi per il tempo della migrazione"
SERVIZI_FERMI=1
systemctl stop ilo-monitor-collector.timer 2>/dev/null || true
systemctl stop ilo-monitor-collector.service 2>/dev/null || true
systemctl stop ilo-monitor.service 2>/dev/null || true

# Se una raccolta manuale e' in corso, aspettiamo che finisca.
for _ in $(seq 1 60); do
    if pgrep -f "app.redfish_collector" >/dev/null 2>&1; then
        printf '     raccolta ancora in corso, attendo...\r'
        sleep 5
    else
        break
    fi
done
echo

# lock_wait_timeout evita che un blocco imprevisto faccia aspettare
# per sempre: meglio un errore chiaro dopo 60 secondi.
{
    echo "SET SESSION lock_wait_timeout = 60;"
    cat "$SRC/sql/02-migrazione.sql"
} | mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
    || die "migrazione del database non riuscita"

say "     schema aggiornato"

# ------------------------------------------------------------
say "4/7  Pulizia degli eventi duplicati"
# ------------------------------------------------------------
# Fino alla correzione del 18/09 il numero progressivo dell'evento
# veniva letto dal posto sbagliato e restava NULL: la chiave unica
# non scattava e ogni raccolta reinseriva l'intero log iLO.
# Le righe senza numero vengono eliminate e reimportate dall'iLO
# alla prossima raccolta, questa volta senza duplicarsi.
DUPES="$(mysql -N -B -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
    -e "SELECT COUNT(*) FROM ilo_events WHERE event_number IS NULL" \
    2>/dev/null || echo 0)"
[[ "$DUPES" =~ ^[0-9]+$ ]] || DUPES=0

if [ "$DUPES" -gt 0 ]; then
    say "     $DUPES eventi senza numero progressivo, li rimuovo"
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
        -e "DELETE FROM ilo_events WHERE event_number IS NULL" \
        || warn "pulizia non riuscita, il conteggio eventi restera' gonfiato"
    say "     verranno reimportati alla prossima raccolta"
else
    say "     nessun duplicato da rimuovere"
fi

# Ogni server deve avere la sua riga di configurazione avvisi.
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
    -e "INSERT IGNORE INTO server_alerts (server_id) SELECT id FROM servers" \
    2>/dev/null || true

# ------------------------------------------------------------
say "5/7  Utente di accesso all'interfaccia"
# ------------------------------------------------------------
UTENTI="$(mysql -N -B -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
    -e "SELECT COUNT(*) FROM app_users" 2>/dev/null || echo 0)"
[[ "$UTENTI" =~ ^[0-9]+$ ]] || UTENTI=0

NUOVO_UTENTE=0
if [ "$UTENTI" -eq 0 ]; then
    # Nessun utente: ne creiamo uno con password casuale, mostrata una
    # sola volta a fine installazione. Va cambiata al primo accesso.
    PASSWORD="$(tr -dc 'A-Za-z0-9!@#%_=+-' </dev/urandom | head -c 18)"
    HASH="$(ILO_MONITOR_BASE="$BASE" PW="$PASSWORD" "$BASE/venv/bin/python" -c \
"import os, sys
sys.path.insert(0, '$BASE')
from app.auth import hash_password
print(hash_password(os.environ['PW']))")"
    if [ -z "$HASH" ]; then
        warn "creazione dell'utente non riuscita: usa ilo-monitor-user add admin"
    else
        mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
            -e "INSERT INTO app_users (username, password_hash, must_change_password) VALUES ('admin', '$HASH', 1)" \
            && NUOVO_UTENTE=1 && say "     creato l'utente 'admin'" \
            || warn "utente non creato: usa ilo-monitor-user add admin"
    fi
else
    say "     $UTENTI utenti gia' configurati, non tocco nulla"
fi

# ------------------------------------------------------------
say "6/7  Servizi"
# ------------------------------------------------------------
UNITS_CHANGED=0
for unit in ilo-monitor.service ilo-monitor-collector.service \
            ilo-monitor-collector.timer; do
    if ! cmp -s "$SRC/systemd/$unit" "/etc/systemd/system/$unit"; then
        # Il timer porta l'intervallo scelto dall'utente: lo conserviamo.
        if [ "$unit" = "ilo-monitor-collector.timer" ] \
           && [ -f "/etc/systemd/system/$unit" ]; then
            CURRENT="$(grep -oP '^OnUnitActiveSec=\K.*' \
                "/etc/systemd/system/$unit" || true)"
        else
            CURRENT=""
        fi
        cp -a "/etc/systemd/system/$unit" "$BACKUP/$unit" 2>/dev/null || true
        install -m 644 "$SRC/systemd/$unit" "/etc/systemd/system/$unit"
        if [ -n "$CURRENT" ]; then
            sed -i "s/^OnUnitActiveSec=.*/OnUnitActiveSec=${CURRENT}/" \
                "/etc/systemd/system/$unit"
            say "     intervallo di raccolta mantenuto a $CURRENT"
        fi
        UNITS_CHANGED=1
    fi
done

if [ "$UNITS_CHANGED" -eq 1 ]; then
    systemctl daemon-reload
    systemctl restart ilo-monitor-collector.timer
    say "     unita' systemd aggiornate"
else
    say "     unita' systemd gia' aggiornate"
fi

systemctl start ilo-monitor-collector.timer 2>/dev/null || true
systemctl restart ilo-monitor.service
SERVIZI_FERMI=0

# ------------------------------------------------------------
say "7/7  Verifica"
# ------------------------------------------------------------
sleep 3
HEALTH="$(curl -s --max-time 10 http://127.0.0.1:8000/api/health || true)"
if printf '%s' "$HEALTH" | grep -q '"ok":true'; then
    say "API attiva: $HEALTH"
else
    warn "L'API non risponde. Ultime righe di log:"
    journalctl -u ilo-monitor.service -n 30 --no-pager || true
    warn "Ripristino i file precedenti da $BACKUP"
    cp -a "$BACKUP/app/." "$BASE/app/"
    cp -a "$BASE/web/index.html" "$BACKUP/index.html.fallita" 2>/dev/null || true
    cp -a "$BACKUP/web/." "$BASE/web/"
    systemctl restart ilo-monitor.service
    die "aggiornamento annullato, versione precedente ripristinata"
fi

SERVERS="$(cd "$BASE" && venv/bin/python -m app.redfish_collector --list \
    2>/dev/null | wc -l)"

echo
echo "============================================================"
echo " AGGIORNAMENTO COMPLETATO"
echo "============================================================"
echo
echo " Interfaccia   : http://$(hostname -I | awk '{print $1}')/"
if [ "$NUOVO_UTENTE" -eq 1 ]; then
echo
echo " ------------------------------------------------------------"
echo "  ACCESSO CREATO - annota adesso, non verra' piu' mostrato"
echo
echo "    utente   : admin"
echo "    password : $PASSWORD"
echo
echo "  Cambiala al primo accesso da Impostazioni."
echo " ------------------------------------------------------------"
fi
echo " Server in elenco: $SERVERS"
echo " Backup        : $BACKUP"
echo
echo " Ricarica la pagina nel browser con Ctrl+Shift+R per"
echo " prendere la nuova interfaccia."
echo
