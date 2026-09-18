#!/usr/bin/env bash
# ============================================================
# Avvio del contenitore.
#
#   entrypoint.sh api        interfaccia web e API (predefinito)
#   entrypoint.sh collector   raccolta periodica dagli iLO
#   entrypoint.sh shell       una shell, per manutenzione
#
# Il primo dei due che parte applica lo schema e crea l'utente
# iniziale; il secondo trova tutto gia' pronto.
# ============================================================

set -euo pipefail

BASE="${ILO_MONITOR_BASE:-/opt/ilo-monitor}"
RUOLO="${1:-api}"

: "${DB_HOST:=db}"
: "${DB_PORT:=3306}"
: "${DB_NAME:=ilomonitor}"
: "${DB_USER:=ilomonitor}"
: "${DB_PASSWORD:?DB_PASSWORD non impostata}"
: "${COLLECT_INTERVAL_MINUTES:=5}"

export DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD ILO_MONITOR_BASE="$BASE"

say(){ printf '\033[1;32m[ilo-monitor]\033[0m %s\n' "$1"; }
warn(){ printf '\033[1;33m[ilo-monitor]\033[0m %s\n' "$1"; }

mysql_cmd(){
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" \
        "$DB_NAME" "$@"
}

# ------------------------------------------------------------
attendi_database(){
    say "attendo il database su $DB_HOST:$DB_PORT"
    for i in $(seq 1 60); do
        if mysql_cmd -e "SELECT 1" >/dev/null 2>&1; then
            say "database raggiungibile"
            return 0
        fi
        sleep 2
    done
    echo "Database non raggiungibile dopo 120 secondi." >&2
    exit 1
}

# ------------------------------------------------------------
applica_schema(){
    # Entrambi gli script sono scritti per poter essere rieseguiti:
    # creano solo cio' che manca.
    say "allineo lo schema"
    mysql_cmd < "$BASE/sql/01-schema.sql"
    mysql_cmd < "$BASE/sql/02-migrazione.sql"
}

# ------------------------------------------------------------
crea_utente_iniziale(){
    local presenti
    presenti="$(mysql_cmd -N -B -e "SELECT COUNT(*) FROM app_users" 2>/dev/null || echo 0)"
    [[ "$presenti" =~ ^[0-9]+$ ]] || presenti=0
    [ "$presenti" -gt 0 ] && return 0

    local utente="${ADMIN_USER:-admin}"
    local password="${ADMIN_PASSWORD:-}"
    local generata=0
    if [ -z "$password" ]; then
        password="$(tr -dc 'A-Za-z0-9!@#%_=+-' </dev/urandom | head -c 18)"
        generata=1
    fi

    local hash
    hash="$(PW="$password" python3 -c "
import os, sys
sys.path.insert(0, '$BASE')
from app.auth import hash_password
print(hash_password(os.environ['PW']))
")"

    mysql_cmd -e "INSERT INTO app_users (username, password_hash, must_change_password)
                  VALUES ('$utente', '$hash', $generata)"

    echo
    echo "============================================================"
    echo " UTENZA CREATA"
    echo
    echo "   utente   : $utente"
    if [ "$generata" -eq 1 ]; then
        echo "   password : $password"
        echo
        echo " Password generata automaticamente: annotala adesso."
        echo " Cambiala al primo accesso da Impostazioni."
    else
        echo "   password : quella indicata in ADMIN_PASSWORD"
    fi
    echo "============================================================"
    echo
}

# ------------------------------------------------------------
case "$RUOLO" in
    api)
        attendi_database
        applica_schema
        crea_utente_iniziale
        # La chiave di cifratura nasce qui se manca. Vive su un volume:
        # perderla rende illeggibili le password iLO salvate.
        python3 -c "
import sys; sys.path.insert(0, '$BASE')
import app.crypto_util  # crea config/secret.key se assente
"
        say "avvio interfaccia su 0.0.0.0:8000"
        exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
        ;;

    collector)
        attendi_database
        # Lo schema lo applica il servizio api: qui aspettiamo che
        # le tabelle ci siano, per non partire su un database a meta'.
        for i in $(seq 1 60); do
            if mysql_cmd -N -B -e "SELECT COUNT(*) FROM settings" >/dev/null 2>&1; then
                break
            fi
            sleep 2
        done

        say "raccolta ogni ${COLLECT_INTERVAL_MINUTES} minuti"
        while true; do
            python3 -m app.redfish_collector || \
                warn "raccolta terminata con errori, riprovo al giro successivo"
            sleep "$((COLLECT_INTERVAL_MINUTES * 60))"
        done
        ;;

    shell)
        exec /bin/bash
        ;;

    *)
        exec "$@"
        ;;
esac
