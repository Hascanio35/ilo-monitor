#!/usr/bin/env bash
# ============================================================
# iLO Monitor - aggiornamento da v1 (singolo server) a v2
#
# Cosa fa:
#   1. salva una copia di sicurezza dell'installazione attuale
#   2. copia i nuovi file applicativi
#   3. applica la migrazione del database
#   4. trasferisce il server gia' configurato nel .env dentro
#      il database, con la password cifrata
#   5. installa i servizi systemd (API + timer del collector)
#   6. riavvia i servizi e verifica che l'API risponda
#
# Puo' essere rieseguito piu' volte senza effetti collaterali.
# Va lanciato come root dalla cartella che contiene questo file.
# ============================================================

set -euo pipefail

BASE="/opt/ilo-monitor"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BASE/backup-$STAMP"

say(){ printf '\n\033[1;32m==>\033[0m %s\n' "$1"; }
warn(){ printf '\033[1;33m    %s\033[0m\n' "$1"; }
die(){ printf '\n\033[1;31mERRORE:\033[0m %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Esegui lo script come root (sudo ./upgrade.sh)"
[ -d "$BASE" ] || die "$BASE non esiste: questo script aggiorna un'installazione esistente"
[ -f "$BASE/config/.env" ] || die "$BASE/config/.env non trovato"
[ -x "$BASE/venv/bin/python" ] || die "Ambiente virtuale non trovato in $BASE/venv"

# ------------------------------------------------------------
say "1/7  Copia di sicurezza in $BACKUP"
# ------------------------------------------------------------
mkdir -p "$BACKUP"
cp -a "$BASE/app" "$BACKUP/app" 2>/dev/null || true
cp -a "$BASE/web" "$BACKUP/web" 2>/dev/null || true
cp -a "$BASE/config" "$BACKUP/config" 2>/dev/null || true

# shellcheck disable=SC1091
set -a; . "$BASE/config/.env"; set +a
: "${DB_NAME:=ilomonitor}"
: "${DB_USER:=ilomonitor}"
: "${DB_HOST:=127.0.0.1}"
[ -n "${DB_PASSWORD:-}" ] || die "DB_PASSWORD assente in config/.env"

DUMP="$BACKUP/$DB_NAME-$STAMP.sql"
if command -v mysqldump >/dev/null 2>&1; then
    mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" \
        --single-transaction "$DB_NAME" > "$DUMP" \
        && say "     dump del database salvato in $DUMP" \
        || warn "dump del database non riuscito, proseguo comunque"
else
    warn "mysqldump non disponibile: nessun dump del database"
fi

# ------------------------------------------------------------
say "2/7  Dipendenze Python"
# ------------------------------------------------------------
"$BASE/venv/bin/pip" install --quiet --upgrade \
    fastapi uvicorn httpx pymysql cryptography python-dotenv pydantic \
    || warn "installazione dipendenze non riuscita: verifica la connessione"

# ------------------------------------------------------------
say "3/7  Copia dei file applicativi"
# ------------------------------------------------------------
mkdir -p "$BASE/app" "$BASE/web" "$BASE/logs" "$BASE/sql" "$BASE/config"

# I vecchi file .bak/.backup-* ingombrano la cartella: li spostiamo
# tutti nel backup invece di lasciarli in giro.
find "$BASE/app" "$BASE/web" -maxdepth 1 -type f \
    \( -name '*.bak*' -o -name '*.backup-*' -o -name '*.before-*' \) \
    -exec mv {} "$BACKUP/" \; 2>/dev/null || true
rm -rf "$BASE/app/__pycache__"

install -m 644 "$SRC/app/__init__.py"          "$BASE/app/__init__.py"
install -m 644 "$SRC/app/crypto_util.py"       "$BASE/app/crypto_util.py"
install -m 644 "$SRC/app/main.py"              "$BASE/app/main.py"
install -m 644 "$SRC/app/redfish_collector.py" "$BASE/app/redfish_collector.py"
install -m 644 "$SRC/web/index.html"           "$BASE/web/index.html"
install -m 644 "$SRC/sql/02-migrazione.sql"        "$BASE/sql/02-migrazione.sql"
install -m 755 "$SRC/bin/ilo-monitor-interval" /usr/local/bin/ilo-monitor-interval

# ------------------------------------------------------------
say "4/7  Migrazione del database"
# ------------------------------------------------------------
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
    < "$SRC/sql/02-migrazione.sql" \
    || die "migrazione del database non riuscita"
say "     schema aggiornato"

# ------------------------------------------------------------
say "5/7  Trasferimento credenziali dal .env al database"
# ------------------------------------------------------------
cd "$BASE"
ILO_MONITOR_BASE="$BASE" "$BASE/venv/bin/python" - <<'PY'
import os
import sys

sys.path.insert(0, "/opt/ilo-monitor")

import pymysql
from dotenv import load_dotenv

load_dotenv("/opt/ilo-monitor/config/.env")
from app.crypto_util import encrypt

ip = os.getenv("ILO_IP")
user = os.getenv("ILO_USER") or "Administrator"
password = os.getenv("ILO_PASSWORD")
name = os.getenv("ILO_NAME") or ip

con = pymysql.connect(
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "ilomonitor"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME", "ilomonitor"),
    charset="utf8mb4",
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor,
)

with con.cursor() as cur:
    cur.execute("SELECT COUNT(*) AS n FROM servers WHERE ilo_password_enc IS NOT NULL")
    already = cur.fetchone()["n"]

    if not (ip and password):
        print("     nessuna credenziale iLO nel .env: niente da trasferire")
    else:
        cur.execute("SELECT id, name FROM servers WHERE ilo_ip=%s", (ip,))
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE servers SET ilo_user=%s, ilo_password_enc=%s WHERE id=%s",
                (user, encrypt(password), row["id"]),
            )
            print(f"     credenziali aggiornate per {row['name']} ({ip})")
        else:
            cur.execute(
                "INSERT INTO servers (name, ilo_ip, ilo_user, ilo_password_enc, enabled) "
                "VALUES (%s,%s,%s,%s,1)",
                (name, ip, user, encrypt(password)),
            )
            print(f"     server {name} ({ip}) inserito in elenco")

    cur.execute(
        "SELECT name, ilo_ip FROM servers WHERE ilo_password_enc IS NULL"
    )
    missing = cur.fetchall()

con.close()

if missing:
    print("")
    print("     ATTENZIONE: questi server non hanno una password salvata e")
    print("     verranno saltati dal collector finche' non la reinserisci")
    print("     dall'interfaccia (Server -> Modifica):")
    for m in missing:
        print(f"       - {m['name']} ({m['ilo_ip']})")
PY

chmod 600 "$BASE/config/secret.key" 2>/dev/null || true

# Le credenziali iLO ora vivono nel database: le togliamo dal .env
# per non lasciarne due copie in giro. Restano nel backup.
if grep -q '^ILO_PASSWORD=' "$BASE/config/.env"; then
    sed -i \
        -e 's/^ILO_PASSWORD=.*/# ILO_PASSWORD spostata nel database (tabella servers)/' \
        -e 's/^ILO_NAME=/# ILO_NAME=/' \
        -e 's/^ILO_IP=/# ILO_IP=/' \
        -e 's/^ILO_USER=/# ILO_USER=/' \
        "$BASE/config/.env"
    say "     credenziali iLO rimosse da config/.env"
fi
chmod 600 "$BASE/config/.env"

# ------------------------------------------------------------
say "6/7  Servizi systemd"
# ------------------------------------------------------------
install -m 644 "$SRC/systemd/ilo-monitor.service" \
    /etc/systemd/system/ilo-monitor.service
install -m 644 "$SRC/systemd/ilo-monitor-collector.service" \
    /etc/systemd/system/ilo-monitor-collector.service
install -m 644 "$SRC/systemd/ilo-monitor-collector.timer" \
    /etc/systemd/system/ilo-monitor-collector.timer

# Allinea l'intervallo del timer al valore salvato nelle impostazioni.
INTERVAL="$(mysql -N -B -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
    -e "SELECT setting_value FROM settings WHERE setting_key='collect_interval_minutes'" \
    2>/dev/null || echo 5)"
[[ "$INTERVAL" =~ ^[0-9]+$ ]] || INTERVAL=5
sed -i "s/^OnUnitActiveSec=.*/OnUnitActiveSec=${INTERVAL}min/" \
    /etc/systemd/system/ilo-monitor-collector.timer

systemctl daemon-reload
systemctl enable --now ilo-monitor-collector.timer >/dev/null
systemctl enable ilo-monitor.service >/dev/null
systemctl restart ilo-monitor.service
say "     API riavviata, timer di raccolta ogni ${INTERVAL} minuti"

if [ -f "$SRC/nginx/ilo-monitor.conf" ] && [ -d /etc/nginx/sites-available ]; then
    cp -a /etc/nginx/sites-available/ilo-monitor.conf \
        "$BACKUP/nginx-ilo-monitor.conf" 2>/dev/null || true
    install -m 644 "$SRC/nginx/ilo-monitor.conf" \
        /etc/nginx/sites-available/ilo-monitor.conf
    ln -sf /etc/nginx/sites-available/ilo-monitor.conf \
        /etc/nginx/sites-enabled/ilo-monitor.conf
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx
        say "     nginx ricaricato"
    else
        warn "configurazione nginx non valida: ripristino quella precedente"
        cp -a "$BACKUP/nginx-ilo-monitor.conf" \
            /etc/nginx/sites-available/ilo-monitor.conf 2>/dev/null || true
    fi
fi

# ------------------------------------------------------------
say "7/7  Verifica"
# ------------------------------------------------------------
sleep 3
HEALTH="$(curl -s --max-time 10 http://127.0.0.1:8000/api/health || true)"
if printf '%s' "$HEALTH" | grep -q '"ok":true'; then
    say "API attiva: $HEALTH"
else
    warn "L'API non risponde correttamente. Log:"
    journalctl -u ilo-monitor.service -n 30 --no-pager || true
    die "aggiornamento completato ma l'API non parte"
fi

say "Prima raccolta dati in corso (puo' richiedere qualche minuto)"
systemctl start ilo-monitor-collector.service || \
    warn "raccolta non avviata: controlla $BASE/logs/collector.log"

echo
echo "============================================================"
echo " AGGIORNAMENTO COMPLETATO"
echo "============================================================"
echo
echo " Interfaccia      : http://$(hostname -I | awk '{print $1}')/"
echo " Copia di backup  : $BACKUP"
echo " Log collector    : $BASE/logs/collector.log"
echo
echo " Comandi utili:"
echo "   systemctl status ilo-monitor"
echo "   systemctl list-timers ilo-monitor-collector.timer"
echo "   $BASE/venv/bin/python -m app.redfish_collector --list"
echo "   ilo-monitor-interval 10        # cambia l'intervallo di raccolta"
echo
echo " Aggiungi gli altri server dal pulsante 'Aggiungi server'."
echo
