"""API HTTP di iLO Monitor.

Espone la dashboard (web/index.html) e tutti gli endpoint usati
dall'interfaccia: elenco e dettaglio server, aggiunta/modifica/rimozione,
raccolta su richiesta, eventi, mappe termiche, report e impostazioni.
"""

import hashlib
import json
import os
import re
import secrets
import threading
import traceback
from datetime import datetime
from typing import Optional

import pymysql
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from pydantic import BaseModel, Field

from app import alerts, auth, mailer
from app import redfish_collector as collector
from app.crypto_util import decrypt, encrypt

BASE_DIR = os.getenv("ILO_MONITOR_BASE", "/opt/ilo-monitor")
load_dotenv(f"{BASE_DIR}/config/.env")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "ilomonitor")
DB_USER = os.getenv("DB_USER", "ilomonitor")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

app = FastAPI(title="HPE iLO Monitor", version="2.1")

SESSION_COOKIE = "ilo_session"

# Percorsi raggiungibili senza aver effettuato l'accesso. Tutto il
# resto passa dal controllo: e' piu' sicuro elencare le eccezioni che
# ricordarsi di proteggere ogni nuovo endpoint.
PUBLIC_PATHS = {
    "/login",
    "/api/login",
    "/api/health",
    "/favicon.ico",
    "/manifest.webmanifest",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    # Lo script per Windows si autentica con la propria chiave, non
    # con la sessione dell'interfaccia: il controllo e' nell'endpoint.
    "/api/agent/drives",
}

# Limite ai tentativi falliti per indirizzo, per rallentare chi prova
# password a raffica.
MAX_FAILED_ATTEMPTS = 8
ATTEMPT_WINDOW_MINUTES = 15

# Evita che due raccolte dello stesso server si accavallino.
_collect_locks = {}
_locks_guard = threading.Lock()


def _lock_for(server_id):
    with _locks_guard:
        if server_id not in _collect_locks:
            _collect_locks[server_id] = threading.Lock()
        return _collect_locks[server_id]


def db():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        # Una query dell'interfaccia che supera i 25 secondi viene
        # interrotta da MariaDB: il browser ha gia' rinunciato a 30, e
        # lasciarla girare fa solo accumulare query a ogni aggiornamento
        # automatico, rallentando tutto il resto.
        init_command="SET SESSION max_statement_time=25",
    )


def one(cur, sql, args=()):
    cur.execute(sql, args)
    return cur.fetchone()


def many(cur, sql, args=()):
    cur.execute(sql, args)
    return cur.fetchall()


def latest_by(cur, table, group_column, server_id):
    """Componenti rilevati nell'ultima raccolta.

    Ci limitiamo all'istante piu' recente invece di prendere
    l'ultima riga di ogni componente mai visto: altrimenti restano
    in elenco i pezzi rimossi, e quando un server viene letto per
    vie diverse (Redfish standard o SmartStorage) gli stessi dischi
    comparirebbero due volte con sigle differenti.
    """
    sql = f"""
        SELECT t.*
        FROM {table} t
        JOIN (
            SELECT MAX(id) AS id
            FROM {table}
            WHERE server_id=%s
              AND collected_at = (
                  SELECT MAX(collected_at) FROM {table} WHERE server_id=%s
              )
            GROUP BY {group_column}
        ) x ON x.id=t.id
        ORDER BY t.id
    """
    return many(cur, sql, (server_id, server_id))


# Dischi: due sorgenti per server, l'iLO e lo script per Windows. Ogni
# sorgente scrive con i propri tempi, quindi "l'ultima raccolta" va
# presa per sorgente, altrimenti l'una nasconderebbe l'altra. I dati
# dello script valgono finche' sono recenti: se lo si disinstalla,
# dopo due giorni i suoi dischi spariscono dall'elenco.
ULTIMI_DISCHI_SQL = """
    SELECT d.* FROM physical_drives d
    JOIN (
        SELECT COALESCE(source, 'ilo') AS src, MAX(collected_at) AS ultimo
        FROM physical_drives WHERE server_id=%s
        GROUP BY COALESCE(source, 'ilo')
    ) u ON u.src = COALESCE(d.source, 'ilo') AND u.ultimo = d.collected_at
    WHERE d.server_id=%s
      AND (COALESCE(d.source, 'ilo') = 'ilo'
           OR d.collected_at >= UTC_TIMESTAMP() - INTERVAL 2 DAY)
    ORDER BY COALESCE(d.source, 'ilo'), d.id
"""


def senza_doppioni(dischi):
    """Un disco visto sia dall'iLO sia da Windows compare una volta sola:
    resta la voce dell'iLO, completata con i contatori SMART di Windows."""
    da_ilo = {}
    for d in dischi:
        sn = str(d.get("serial_number") or "").strip().upper()
        if sn and (d.get("source") or "ilo") == "ilo":
            da_ilo[sn] = d
    esito = []
    for d in dischi:
        sn = str(d.get("serial_number") or "").strip().upper()
        if (d.get("source") or "ilo") == "os" and sn in da_ilo:
            base = da_ilo[sn]
            for campo in ("temperature_c", "uncorrected_errors", "smart_json",
                          "power_on_hours", "media_life_left_percent"):
                if base.get(campo) is None and d.get(campo) is not None:
                    base[campo] = d[campo]
            continue
        esito.append(d)
    return esito


def ultimi_dischi(cur, server_id):
    return senza_doppioni(
        many(cur, ULTIMI_DISCHI_SQL, (server_id, server_id)))


def public_server(row):
    """Rimuove password e token di sessione prima di inviare al browser."""
    if not row:
        return row
    clean = dict(row)
    clean.pop("ilo_password_enc", None)
    clean.pop("ilo_session_token", None)
    clean.pop("ilo_session_location", None)
    clean["has_agent"] = bool(row.get("agent_token_hash"))
    clean.pop("agent_token_hash", None)
    clean["has_password"] = bool(row.get("ilo_password_enc"))
    return clean


@app.exception_handler(Exception)
async def errore_non_gestito(request: Request, exc: Exception):
    """Restituisce il motivo vero invece di 'Internal Server Error'.

    L'interfaccia e' raggiungibile solo da utenti autenticati sulla
    rete di gestione, quindi mostrare il messaggio di errore fa
    risparmiare mezz'ora di ricerca nei log a ogni intoppo. Il
    dettaglio completo finisce comunque nel journal.
    """
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "ok": False,
            "detail": f"{type(exc).__name__}: {exc}",
            "path": request.url.path,
        },
    )


# ================================================================
# AUTENTICAZIONE
# ================================================================
#
# I modelli stanno prima degli endpoint che li usano: FastAPI
# risolve le annotazioni quando registra la rotta, non a runtime.


class LoginIn(BaseModel):
    username: str
    password: str


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


def session_hours(cur):
    try:
        cur.execute(
            "SELECT setting_value FROM settings "
            "WHERE setting_key='session_hours'"
        )
        row = cur.fetchone()
        return max(1, int(row["setting_value"])) if row else 12
    except Exception:
        return 12


def lookup_session(token):
    """Utente associato a un token valido, None se assente o scaduto."""
    if not token:
        return None
    con = db()
    try:
        with con.cursor() as cur:
            row = one(
                cur,
                """
                SELECT s.token, s.expires_at, u.id, u.username, u.full_name,
                       u.must_change_password
                FROM app_sessions s
                JOIN app_users u ON u.id = s.user_id
                WHERE s.token=%s AND s.expires_at > NOW()
                """,
                (token,),
            )
            if row:
                # La sessione si rinnova finche' viene usata.
                cur.execute(
                    "UPDATE app_sessions SET last_seen_at=NOW(), "
                    "expires_at = NOW() + INTERVAL %s HOUR WHERE token=%s",
                    (session_hours(cur), token),
                )
            return row
    except Exception:
        # Se le tabelle non esistono ancora (migrazione non applicata)
        # non blocchiamo l'accesso: lo dira' la pagina di login.
        return None
    finally:
        con.close()


def failed_attempts(cur, client_ip):
    row = one(
        cur,
        """
        SELECT COUNT(*) AS n FROM login_attempts
        WHERE client_ip=%s AND success=0
          AND attempted_at > NOW() - INTERVAL %s MINUTE
        """,
        (client_ip, ATTEMPT_WINDOW_MINUTES),
    )
    return int(row["n"]) if row else 0


def any_user_exists():
    con = db()
    try:
        with con.cursor() as cur:
            row = one(cur, "SELECT COUNT(*) AS n FROM app_users")
            return bool(row and row["n"])
    except Exception:
        return False
    finally:
        con.close()


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if (path in PUBLIC_PATHS
            or path.startswith("/static/")
            or path.startswith("/icons/")):
        return await call_next(request)

    user = lookup_session(request.cookies.get(SESSION_COOKIE))
    if not user:
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": "Accesso richiesto"},
            )
        return RedirectResponse("/login", status_code=302)

    request.state.user = user
    return await call_next(request)


# Senza Cache-Control il browser puo' riusare la pagina vecchia per
# ore (cache "euristica" basata sulla data del file) e dopo un
# aggiornamento si continua a vedere l'interfaccia precedente.
# no-cache non vieta la cache: obbliga a chiedere se e' cambiata.
NO_CACHE = {"Cache-Control": "no-cache"}


@app.get("/login")
def login_page():
    return FileResponse(f"{BASE_DIR}/web/login.html", headers=NO_CACHE)


@app.post("/api/login")
def login(payload: LoginIn, request: Request, response: Response):
    client_ip = request.client.host if request.client else None
    con = db()
    try:
        with con.cursor() as cur:
            if failed_attempts(cur, client_ip) >= MAX_FAILED_ATTEMPTS:
                raise HTTPException(
                    429,
                    "Troppi tentativi falliti da questo indirizzo. "
                    f"Riprova fra {ATTEMPT_WINDOW_MINUTES} minuti.",
                )

            user = one(
                cur,
                "SELECT * FROM app_users WHERE username=%s",
                (payload.username.strip(),),
            )

            # Verifichiamo l'hash anche quando l'utente non esiste, per
            # non rivelare dai tempi di risposta quali nomi sono validi.
            stored = user["password_hash"] if user else auth.hash_password(
                "segnaposto"
            )
            valido = auth.verify_password(payload.password, stored)

            cur.execute(
                """
                INSERT INTO login_attempts
                (username, client_ip, attempted_at, success)
                VALUES (%s,%s,NOW(),%s)
                """,
                (payload.username.strip()[:100], client_ip,
                 1 if (user and valido) else 0),
            )

            if not user or not valido:
                raise HTTPException(401, "Nome utente o password non validi")

            token = auth.new_session_token()[:64]
            ore = session_hours(cur)
            cur.execute(
                """
                INSERT INTO app_sessions
                (token, user_id, created_at, expires_at, last_seen_at,
                 client_ip)
                VALUES (%s,%s,NOW(),NOW() + INTERVAL %s HOUR,NOW(),%s)
                """,
                (token, user["id"], ore, client_ip),
            )
            cur.execute(
                "UPDATE app_users SET last_login_at=NOW() WHERE id=%s",
                (user["id"],),
            )
            # Vecchie sessioni scadute: le togliamo di mezzo.
            cur.execute("DELETE FROM app_sessions WHERE expires_at < NOW()")

            response.set_cookie(
                SESSION_COOKIE,
                token,
                max_age=ore * 3600,
                httponly=True,
                samesite="lax",
                path="/",
            )
            return {
                "ok": True,
                "data": {
                    "username": user["username"],
                    "full_name": user["full_name"],
                    "must_change_password": bool(
                        user["must_change_password"]
                    ),
                },
            }
    finally:
        con.close()


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        con = db()
        try:
            with con.cursor() as cur:
                cur.execute(
                    "DELETE FROM app_sessions WHERE token=%s", (token,)
                )
        finally:
            con.close()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Accesso richiesto")
    return {
        "ok": True,
        "data": {
            "username": user["username"],
            "full_name": user["full_name"],
            "must_change_password": bool(user["must_change_password"]),
        },
    }


@app.post("/api/change-password")
def change_password(payload: PasswordIn, request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Accesso richiesto")

    debole = auth.check_password_strength(
        payload.new_password, user["username"]
    )
    if debole:
        raise HTTPException(400, debole)

    con = db()
    try:
        with con.cursor() as cur:
            row = one(
                cur,
                "SELECT password_hash FROM app_users WHERE id=%s",
                (user["id"],),
            )
            if not row or not auth.verify_password(
                payload.current_password, row["password_hash"]
            ):
                raise HTTPException(401, "Password attuale non corretta")

            cur.execute(
                "UPDATE app_users SET password_hash=%s, "
                "must_change_password=0 WHERE id=%s",
                (auth.hash_password(payload.new_password), user["id"]),
            )
            # Cambiare password chiude le altre sessioni aperte.
            cur.execute(
                "DELETE FROM app_sessions WHERE user_id=%s AND token<>%s",
                (user["id"], request.cookies.get(SESSION_COOKIE)),
            )
            return {"ok": True, "message": "Password aggiornata"}
    finally:
        con.close()


# ================================================================
# MODELLI DI INPUT
# ================================================================



class ServerIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=150)
    ilo_ip: str = Field(min_length=1, max_length=45)
    ilo_user: str = Field(default="Administrator", max_length=150)
    ilo_password: Optional[str] = None
    server_group: Optional[str] = None
    notes: Optional[str] = None
    enabled: bool = True


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    ilo_ip: Optional[str] = None
    ilo_user: Optional[str] = None
    ilo_password: Optional[str] = None
    server_group: Optional[str] = None
    notes: Optional[str] = None
    enabled: Optional[bool] = None


class TestIn(BaseModel):
    ilo_ip: str
    ilo_user: str = "Administrator"
    ilo_password: Optional[str] = None
    server_id: Optional[int] = None


class PowerIn(BaseModel):
    action: str


class SmtpIn(BaseModel):
    smtp_enabled: Optional[int] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_security: Optional[str] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_to: Optional[str] = None
    alert_max_per_run: Optional[int] = None


class AlertRuleIn(BaseModel):
    enabled: Optional[bool] = None
    min_severity: Optional[str] = None
    cat_storage: Optional[bool] = None
    cat_fans: Optional[bool] = None
    cat_thermal: Optional[bool] = None
    cat_power: Optional[bool] = None
    cat_memory: Optional[bool] = None
    cat_cpu: Optional[bool] = None
    cat_network: Optional[bool] = None
    cat_other: Optional[bool] = None
    alert_temperature: Optional[bool] = None
    alert_drives: Optional[bool] = None
    alert_psu_fans: Optional[bool] = None
    alert_unreachable: Optional[bool] = None
    apply_to_all: Optional[bool] = False


class SettingsIn(BaseModel):
    temp_warning_c: Optional[float] = None
    temp_critical_c: Optional[float] = None
    collect_interval_minutes: Optional[int] = None
    ui_refresh_seconds: Optional[int] = None
    retention_days: Optional[int] = None
    ignore_login_events: Optional[int] = None
    inventory_interval_minutes: Optional[int] = None


# ================================================================
# PAGINA E SALUTE
# ================================================================


@app.get("/")
def index():
    return FileResponse(f"{BASE_DIR}/web/index.html", headers=NO_CACHE)


# ---------- icone e manifesto ----------
# iOS cerca /apple-touch-icon.png alla radice e non legge il
# manifesto; Android usa il manifesto. Serviamo entrambi.

ICONE = {
    "/apple-touch-icon.png": "apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png": "apple-touch-icon.png",
    "/icons/icon-192.png": "icon-192.png",
    "/icons/icon-512.png": "icon-512.png",
    "/icons/favicon-32.png": "favicon-32.png",
    "/icons/favicon-64.png": "favicon-64.png",
}


@app.get("/favicon.ico")
def favicon():
    return FileResponse(
        f"{BASE_DIR}/web/icons/favicon-32.png", media_type="image/png"
    )


@app.get("/manifest.webmanifest")
def manifest():
    return FileResponse(
        f"{BASE_DIR}/web/manifest.webmanifest",
        media_type="application/manifest+json",
    )


@app.get("/apple-touch-icon.png")
@app.get("/apple-touch-icon-precomposed.png")
def apple_icon():
    return FileResponse(
        f"{BASE_DIR}/web/icons/apple-touch-icon.png", media_type="image/png"
    )


@app.get("/icons/{nome}")
def icona(nome: str):
    percorso = ICONE.get(f"/icons/{nome}")
    if not percorso:
        raise HTTPException(404, "Icona non trovata")
    return FileResponse(
        f"{BASE_DIR}/web/icons/{percorso}", media_type="image/png"
    )


@app.get("/api/health")
def health():
    try:
        con = db()
        try:
            with con.cursor() as cur:
                one(cur, "SELECT 1 AS ok")
        finally:
            con.close()
        return {"ok": True, "service": "ilo-monitor", "database": "ok"}
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"ok": False, "service": "ilo-monitor", "error": str(exc)},
        )


# ================================================================
# RIEPILOGO
# ================================================================


@app.get("/api/summary")
def summary():
    con = db()
    try:
        with con.cursor() as cur:
            thresholds = get_settings_dict(cur)
            warn_c = float(thresholds.get("temp_warning_c", 55))
            crit_c = float(thresholds.get("temp_critical_c", 70))

            servers = many(
                cur,
                "SELECT id, overall_health, last_collect_status "
                "FROM servers WHERE enabled=1",
            )
            for row in servers:
                ultimi = ultimi_valori(cur, row["id"])
                row["ambient_temp"] = ultimi["ambient_temperature"]
                row["max_temp"] = ultimi["max_temperature"]
                row["watts"] = ultimi["consumed_watts"]

            temps = [
                float(x["ambient_temp"])
                for x in servers
                if x["ambient_temp"] is not None
            ]
            peaks = [
                float(x["max_temp"])
                for x in servers
                if x["max_temp"] is not None
            ]
            misurati = [
                float(x["watts"]) for x in servers if x["watts"] is not None
            ]
            total_power = sum(misurati)

            def bucket(row):
                health = str(row["overall_health"] or "").upper()
                if row["last_collect_status"] == "ERROR" or health in (
                    "CRITICAL",
                    "FAILED",
                ):
                    return "critical"
                if health == "OK":
                    return "ok"
                if not health:
                    return "unknown"
                return "warning"

            buckets = [bucket(x) for x in servers]

            events = one(
                cur,
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN UPPER(severity) IN ('CRITICAL','FATAL')
                             THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN UPPER(severity)='WARNING'
                             THEN 1 ELSE 0 END) AS warning,
                    SUM(CASE WHEN UPPER(severity) NOT IN
                             ('CRITICAL','FATAL','WARNING')
                             OR severity IS NULL
                             THEN 1 ELSE 0 END) AS informational
                FROM ilo_events
                WHERE event_created >= NOW() - INTERVAL 24 HOUR
                """,
            )

            return {
                "ok": True,
                "data": {
                    "total_servers": len(servers),
                    "ok_servers": buckets.count("ok"),
                    "warning_servers": buckets.count("warning")
                    + buckets.count("unknown"),
                    "critical_servers": buckets.count("critical"),
                    "avg_temperature": round(sum(temps) / len(temps), 1)
                    if temps
                    else None,
                    "min_temperature": min(temps) if temps else None,
                    "max_temperature": max(temps) if temps else None,
                    "peak_temperature": max(peaks) if peaks else None,
                    "total_power": round(total_power, 1),
                    # La media si fa sui server che misurano il consumo:
                    # contare anche quelli senza misura la abbasserebbe.
                    "avg_power": round(total_power / len(misurati), 1)
                    if misurati
                    else None,
                    "power_measured": len(misurati),
                    "events_24h": int(events["total"] or 0),
                    "events_critical": int(events["critical"] or 0),
                    "events_warning": int(events["warning"] or 0),
                    "events_info": int(events["informational"] or 0),
                    "temp_warning_c": warn_c,
                    "temp_critical_c": crit_c,
                },
            }
    finally:
        con.close()


# ================================================================
# ELENCO E DETTAGLIO SERVER
# ================================================================

# ----------------------------------------------------------------
# Ultimi valori di un server
# ----------------------------------------------------------------
# Prima erano sottoquery correlate dentro un'unica SELECT. Con qualche
# settimana di storico MariaDB a volte sceglieva di scorrere le tabelle
# intere invece di saltare all'ultima riga, e la panoramica superava
# i 30 secondi. Qui ogni lettura e' una query semplice sul solo server,
# ordinata come l'indice (server_id, collected_at): una riga letta,
# qualunque sia la quantita' di storico.


def ultima_riga(cur, tabella, server_id, colonne):
    return one(
        cur,
        f"SELECT {colonne} FROM {tabella} WHERE server_id=%s "
        f"ORDER BY collected_at DESC LIMIT 1",
        (server_id,),
    ) or {}


def ultimi_valori(cur, server_id):
    sm = ultima_riga(
        cur, "system_metrics", server_id,
        "collected_at, cpu_utilization, cpu_power_watts, "
        "ambient_temperature, io_bus_utilization, memory_bus_utilization",
    )
    pm = ultima_riga(
        cur, "power_metrics", server_id, "consumed_watts, average_watts"
    )

    # Sensori dell'ultima raccolta: picco e, se l'iLO non riporta
    # AmbTemp, la temperatura del sensore d'aspirazione (Inlet).
    ultima_termica = one(
        cur,
        "SELECT MAX(collected_at) AS t FROM thermal_sensors "
        "WHERE server_id=%s",
        (server_id,),
    )
    sensori = []
    if ultima_termica and ultima_termica["t"]:
        sensori = many(
            cur,
            "SELECT sensor_name, temperature_c FROM thermal_sensors "
            "WHERE server_id=%s AND collected_at=%s",
            (server_id, ultima_termica["t"]),
        )
    temperature = [
        float(x["temperature_c"]) for x in sensori
        if x["temperature_c"] is not None and float(x["temperature_c"]) > 0
    ]
    inlet = next(
        (
            float(x["temperature_c"]) for x in sensori
            if "inlet" in str(x["sensor_name"] or "").lower()
            and x["temperature_c"] is not None
            and float(x["temperature_c"]) > 0
        ),
        None,
    )
    ambiente = sm.get("ambient_temperature")
    if ambiente is None:
        ambiente = inlet

    eventi = one(
        cur,
        "SELECT COUNT(*) AS n FROM ilo_events "
        "WHERE server_id=%s AND event_created >= NOW() - INTERVAL 24 HOUR",
        (server_id,),
    )

    return {
        "metrics_at": sm.get("collected_at"),
        "cpu_utilization": sm.get("cpu_utilization"),
        "cpu_power_watts": sm.get("cpu_power_watts"),
        "ambient_temperature": ambiente,
        "io_bus_utilization": sm.get("io_bus_utilization"),
        "memory_bus_utilization": sm.get("memory_bus_utilization"),
        "consumed_watts": pm.get("consumed_watts"),
        "average_watts": pm.get("average_watts"),
        "max_temperature": max(temperature) if temperature else None,
        "events_24h": int(eventi["n"]) if eventi else 0,
    }


@app.get("/api/servers")
def servers(include_disabled: bool = Query(True)):
    where = "" if include_disabled else "WHERE s.enabled=1"
    con = db()
    try:
        with con.cursor() as cur:
            rows = many(cur, f"SELECT s.* FROM servers s {where} ORDER BY s.name")
            for row in rows:
                row.update(ultimi_valori(cur, row["id"]))
            return {"ok": True, "data": [public_server(r) for r in rows]}
    finally:
        con.close()


@app.get("/api/servers/{server_id}")
def server_detail(server_id: int):
    con = db()
    try:
        with con.cursor() as cur:
            s = one(cur, "SELECT * FROM servers WHERE id=%s", (server_id,))
            if not s:
                raise HTTPException(404, "Server non trovato")
            s.update(ultimi_valori(cur, server_id))

            return {
                "ok": True,
                "data": {
                    "server": public_server(s),
                    "metric": one(
                        cur,
                        "SELECT * FROM system_metrics WHERE server_id=%s "
                        "ORDER BY collected_at DESC, id DESC LIMIT 1",
                        (server_id,),
                    ),
                    "power": one(
                        cur,
                        "SELECT * FROM power_metrics WHERE server_id=%s "
                        "ORDER BY collected_at DESC, id DESC LIMIT 1",
                        (server_id,),
                    ),
                    # La media dell'iLO copre solo gli ultimi minuti
                    # (IntervalInMin, di solito 20): quella di 24 ore la
                    # ricaviamo dalle rilevazioni archiviate.
                    "power_24h": one(
                        cur,
                        """
                        SELECT AVG(consumed_watts) AS avg_watts,
                               MAX(consumed_watts) AS max_watts,
                               MIN(consumed_watts) AS min_watts,
                               COUNT(consumed_watts) AS samples
                        FROM power_metrics
                        WHERE server_id=%s
                          AND collected_at >= NOW() - INTERVAL 24 HOUR
                        """,
                        (server_id,),
                    ),
                    "fans": latest_by(cur, "fans", "fan_id", server_id),
                    "thermal": latest_by(
                        cur,
                        "thermal_sensors",
                        "sensor_name,sensor_number",
                        server_id,
                    ),
                    "processors": latest_by(
                        cur, "processors", "processor_id", server_id
                    ),
                    "memory": latest_by(
                        cur, "memory_modules", "dimm_id", server_id
                    ),
                    "storage_controllers": latest_by(
                        cur, "storage_controllers", "controller_id", server_id
                    ),
                    "drives": ultimi_dischi(cur, server_id),
                    "volumes": latest_by(
                        cur, "storage_volumes", "volume_id", server_id
                    ),
                    "network": latest_by(
                        cur, "network_interfaces", "interface_id", server_id
                    ),
                    "power_supplies": latest_by(
                        cur, "power_supplies", "psu_id", server_id
                    ),
                    "events": many(
                        cur,
                        "SELECT * FROM ilo_events WHERE server_id=%s "
                        "ORDER BY event_created DESC, id DESC LIMIT 200",
                        (server_id,),
                    ),
                    "runs": many(
                        cur,
                        "SELECT id, started_at, finished_at, status, "
                        "error_message FROM collection_runs "
                        "WHERE server_id=%s ORDER BY started_at DESC, id DESC LIMIT 10",
                        (server_id,),
                    ),
                },
            }
    finally:
        con.close()


@app.get("/api/servers/{server_id}/metrics")
def metrics(server_id: int, hours: int = Query(24, ge=1, le=8760)):
    con = db()
    try:
        with con.cursor() as cur:
            rows = many(
                cur,
                """
                SELECT collected_at, cpu_utilization, cpu_power_watts,
                       io_bus_utilization, memory_bus_utilization,
                       ambient_temperature
                FROM system_metrics
                WHERE server_id=%s AND collected_at >= NOW()-INTERVAL %s HOUR
                ORDER BY collected_at
                """,
                (server_id, hours),
            )
            power = many(
                cur,
                """
                SELECT collected_at, consumed_watts, average_watts,
                       maximum_watts, minimum_watts, cpu_watts, dimm_watts,
                       gpu_watts, power_capacity_watts
                FROM power_metrics
                WHERE server_id=%s AND collected_at >= NOW()-INTERVAL %s HOUR
                ORDER BY collected_at
                """,
                (server_id, hours),
            )
            temps = many(
                cur,
                """
                SELECT collected_at, MAX(temperature_c) AS max_temperature,
                       AVG(temperature_c) AS avg_temperature
                FROM thermal_sensors
                WHERE server_id=%s AND collected_at >= NOW()-INTERVAL %s HOUR
                GROUP BY collected_at
                ORDER BY collected_at
                """,
                (server_id, hours),
            )
            return {
                "ok": True,
                "data": {"metrics": rows, "power": power, "temperatures": temps},
            }
    finally:
        con.close()


# ================================================================
# CRUD SERVER
# ================================================================


@app.post("/api/servers", status_code=201)
def create_server(payload: ServerIn, background: BackgroundTasks):
    if not payload.ilo_password:
        raise HTTPException(400, "La password iLO è obbligatoria")

    # Verifichiamo le credenziali prima di salvare: meglio un errore
    # subito che un server fantasma in elenco.
    try:
        identity, protocollo = collector.identifica(
            payload.ilo_ip, payload.ilo_user, payload.ilo_password
        )
    except Exception as exc:
        raise HTTPException(
            400, f"Connessione all'iLO non riuscita: {exc}"
        ) from exc

    # Il nome è facoltativo: se non arriva dal modulo lo prendiamo
    # dall'iLO, che riporta l'hostname del sistema. In mancanza di
    # quello ripieghiamo su modello e seriale, poi sull'indirizzo.
    name = (payload.name or "").strip()
    if not name:
        name = (identity.get("hostname") or "").strip()
    if not name:
        model = (identity.get("model") or "").strip()
        serial = (identity.get("serial_number") or "").strip()
        name = " ".join(x for x in (model, serial) if x).strip()
    if not name:
        name = payload.ilo_ip
    name = name[:150]

    con = db()
    try:
        with con.cursor() as cur:
            existing = one(
                cur, "SELECT id FROM servers WHERE ilo_ip=%s", (payload.ilo_ip,)
            )
            if existing:
                raise HTTPException(
                    409,
                    f"L'indirizzo {payload.ilo_ip} è già associato a un "
                    f"server in elenco",
                )

            cur.execute(
                """
                INSERT INTO servers
                (name, hostname, ilo_ip, ilo_user, ilo_password_enc,
                 ilo_version, ilo_firmware, manufacturer, model,
                 serial_number, uuid, bios_version, overall_health, state,
                 power_state, processor_summary, processor_count,
                 memory_total_gib, server_group, notes, enabled, last_seen,
                 ilo_license, ilo_protocol)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    name,
                    identity.get("hostname"),
                    payload.ilo_ip,
                    payload.ilo_user,
                    encrypt(payload.ilo_password),
                    identity.get("ilo_version"),
                    identity.get("ilo_firmware"),
                    identity.get("manufacturer"),
                    identity.get("model"),
                    identity.get("serial_number"),
                    identity.get("uuid"),
                    identity.get("bios_version"),
                    identity.get("overall_health"),
                    identity.get("state"),
                    identity.get("power_state"),
                    identity.get("processor_model"),
                    identity.get("processor_count"),
                    identity.get("memory_total_gib"),
                    payload.server_group,
                    payload.notes,
                    1 if payload.enabled else 0,
                    datetime.now(),
                    identity.get("ilo_license"),
                    protocollo,
                ),
            )
            server_id = cur.lastrowid
            cur.execute(
                "INSERT IGNORE INTO server_alerts (server_id) VALUES (%s)",
                (server_id,),
            )
    finally:
        con.close()

    # La prima raccolta completa richiede qualche decina di secondi:
    # la eseguiamo in background e la UI mostra i dati man mano.
    background.add_task(_collect_background, server_id)

    return {
        "ok": True,
        "id": server_id,
        "name": name,
        "identity": identity,
        "message": f"{name} aggiunto. Prima raccolta dati in corso.",
    }


@app.put("/api/servers/{server_id}")
def update_server(server_id: int, payload: ServerUpdate):
    con = db()
    try:
        with con.cursor() as cur:
            current = one(cur, "SELECT * FROM servers WHERE id=%s", (server_id,))
            if not current:
                raise HTTPException(404, "Server non trovato")

            new_ip = payload.ilo_ip or current["ilo_ip"]
            new_user = payload.ilo_user or current["ilo_user"]

            if payload.ilo_ip and payload.ilo_ip != current["ilo_ip"]:
                clash = one(
                    cur,
                    "SELECT id FROM servers WHERE ilo_ip=%s AND id<>%s",
                    (payload.ilo_ip, server_id),
                )
                if clash:
                    raise HTTPException(
                        409, f"L'indirizzo {payload.ilo_ip} è già in elenco"
                    )

            # Se cambiano indirizzo, utente o password, riverifichiamo.
            password_enc = current["ilo_password_enc"]
            if payload.ilo_password:
                password_enc = encrypt(payload.ilo_password)
            credentials_changed = bool(
                payload.ilo_password
                or (payload.ilo_ip and payload.ilo_ip != current["ilo_ip"])
                or (payload.ilo_user and payload.ilo_user != current["ilo_user"])
            )
            protocollo = None
            if credentials_changed:
                try:
                    _, protocollo = collector.identifica(
                        new_ip, new_user, decrypt(password_enc)
                    )
                except Exception as exc:
                    raise HTTPException(
                        400, f"Connessione all'iLO non riuscita: {exc}"
                    ) from exc

            # Un nome svuotato non azzera la riga: torna a quello che
            # l'iLO riporta come hostname, come alla creazione.
            new_name = payload.name
            if new_name is not None and not new_name.strip():
                new_name = (current.get("hostname") or "").strip() \
                    or current["ilo_ip"]

            fields = {
                "name": new_name,
                "ilo_ip": payload.ilo_ip,
                "ilo_user": payload.ilo_user,
            }
            sets, args = [], []
            for column, value in fields.items():
                # Indirizzo e utente non possono restare vuoti.
                if value is not None and str(value).strip():
                    sets.append(f"{column}=%s")
                    args.append(str(value).strip()[:150])
            # Gruppo e note possono invece essere svuotati di proposito.
            for column in ("server_group", "notes"):
                value = getattr(payload, column)
                if value is not None:
                    sets.append(f"{column}=%s")
                    args.append(value.strip() or None)
            if payload.ilo_password:
                sets.append("ilo_password_enc=%s")
                args.append(password_enc)
            if credentials_changed:
                # La sessione memorizzata appartiene alle vecchie
                # credenziali o al vecchio indirizzo: va scartata.
                sets.append("ilo_session_token=NULL")
                sets.append("ilo_session_location=NULL")
                sets.append("ilo_session_at=NULL")
                # Un indirizzo nuovo puo' essere un iLO di altra generazione.
                sets.append("ilo_protocol=%s")
                args.append(protocollo)
            if payload.enabled is not None:
                sets.append("enabled=%s")
                args.append(1 if payload.enabled else 0)

            if sets:
                args.append(server_id)
                cur.execute(
                    f"UPDATE servers SET {', '.join(sets)} WHERE id=%s", args
                )

            updated = one(cur, "SELECT * FROM servers WHERE id=%s", (server_id,))
            return {"ok": True, "data": public_server(updated)}
    finally:
        con.close()


@app.delete("/api/servers/{server_id}")
def delete_server(server_id: int):
    con = db()
    try:
        with con.cursor() as cur:
            row = one(cur, "SELECT name FROM servers WHERE id=%s", (server_id,))
            if not row:
                raise HTTPException(404, "Server non trovato")
            # Le tabelle figlie hanno ON DELETE CASCADE: con molto storico
            # ci vuole tempo, quindi niente limite di durata qui.
            cur.execute("SET SESSION max_statement_time=0")
            cur.execute("DELETE FROM servers WHERE id=%s", (server_id,))
            return {
                "ok": True,
                "message": f"{row['name']} rimosso insieme al suo storico",
            }
    finally:
        con.close()


@app.post("/api/servers/test")
def test_connection(payload: TestIn):
    """Prova le credenziali senza salvare nulla."""
    password = payload.ilo_password
    ip = payload.ilo_ip
    user = payload.ilo_user

    if not password and payload.server_id:
        con = db()
        try:
            with con.cursor() as cur:
                row = one(
                    cur,
                    "SELECT ilo_ip, ilo_user, ilo_password_enc FROM servers "
                    "WHERE id=%s",
                    (payload.server_id,),
                )
                if not row:
                    raise HTTPException(404, "Server non trovato")
                password = decrypt(row["ilo_password_enc"])
                ip = ip or row["ilo_ip"]
                user = user or row["ilo_user"]
        finally:
            con.close()

    if not password:
        raise HTTPException(400, "Password iLO mancante")

    try:
        identity, protocollo = collector.identifica(ip, user, password)
        identity["protocol"] = protocollo
    except Exception as exc:
        return JSONResponse(
            status_code=200, content={"ok": False, "error": str(exc)}
        )
    return {"ok": True, "data": identity}


# ================================================================
# RACCOLTA SU RICHIESTA
# ================================================================


def _collect_background(server_id: int):
    lock = _lock_for(server_id)
    if not lock.acquire(blocking=False):
        return
    try:
        # Stesso lock del collector da riga di comando: se il timer
        # systemd sta gia' raccogliendo, questa richiesta non parte.
        # I dati arriveranno comunque dalla raccolta in corso.
        with collector.run_lock() as ottenuto:
            if not ottenuto:
                print(
                    f"Raccolta server {server_id} rimandata: "
                    f"un'altra raccolta e' in corso"
                )
                return
            collector.collect_one(server_id, verbose=False)
    except Exception as exc:
        print(f"Raccolta server {server_id} fallita: {exc}")
    finally:
        lock.release()


@app.post("/api/servers/{server_id}/collect")
def collect_now(server_id: int, background: BackgroundTasks):
    con = db()
    try:
        with con.cursor() as cur:
            row = one(cur, "SELECT name FROM servers WHERE id=%s", (server_id,))
            if not row:
                raise HTTPException(404, "Server non trovato")
    finally:
        con.close()

    background.add_task(_collect_background, server_id)
    return {"ok": True, "message": f"Raccolta di {row['name']} avviata"}


@app.post("/api/collect")
def collect_all_now(background: BackgroundTasks):
    background.add_task(_collect_all_background)
    return {"ok": True, "message": "Raccolta di tutti i server avviata"}


def _collect_all_background():
    try:
        with collector.run_lock() as ottenuto:
            if not ottenuto:
                print("Raccolta generale rimandata: una e' gia' in corso")
                return
            collector.collect_all(verbose=False)
    except Exception as exc:
        print(f"Raccolta generale fallita: {exc}")


# ================================================================
# AZIONI REDFISH
# ================================================================

POWER_ACTIONS = {
    "on": "On",
    "graceful_shutdown": "GracefulShutdown",
    "force_off": "ForceOff",
    "graceful_restart": "GracefulRestart",
    "force_restart": "ForceRestart",
    "nmi": "Nmi",
}


def _open_session(cur, server_id):
    row = one(cur, "SELECT * FROM servers WHERE id=%s", (server_id,))
    if not row:
        raise HTTPException(404, "Server non trovato")
    password = decrypt(row["ilo_password_enc"])
    if not password:
        raise HTTPException(400, "Password iLO non configurata")
    return row, collector.Redfish(row["ilo_ip"], row["ilo_user"], password)


@app.post("/api/servers/{server_id}/power")
def power_action(server_id: int, payload: PowerIn):
    action = POWER_ACTIONS.get(payload.action.lower())
    if not action:
        raise HTTPException(
            400,
            "Azione non riconosciuta. Valori ammessi: "
            + ", ".join(POWER_ACTIONS),
        )

    con = db()
    try:
        with con.cursor() as cur:
            riga = one(cur, "SELECT * FROM servers WHERE id=%s", (server_id,))
            if riga and riga.get("ilo_protocol") == "ribcl":
                return _power_ribcl(cur, riga, payload.action.lower(), action)
            if riga and riga.get("ilo_protocol") == "bmc":
                return _power_bmc(cur, riga, payload.action.lower())
            row, rf = _open_session(cur, server_id)
            try:
                rf.post(
                    "/Systems/1/Actions/ComputerSystem.Reset/",
                    {"ResetType": action},
                )
                state = rf.get("/Systems/1/").get("PowerState")
                cur.execute(
                    "UPDATE servers SET power_state=%s WHERE id=%s",
                    (state, server_id),
                )
            except Exception as exc:
                raise HTTPException(502, f"iLO ha rifiutato l'azione: {exc}")
            finally:
                rf.close()
            return {
                "ok": True,
                "message": f"Comando {action} inviato a {row['name']}",
                "power_state": state,
            }
    finally:
        con.close()


def _power_ribcl(cur, riga, azione, nome_azione):
    from app import ribcl_collector
    try:
        stato = ribcl_collector.accensione(riga, azione)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"iLO ha rifiutato l'azione: {exc}")
    if stato:
        cur.execute("UPDATE servers SET power_state=%s WHERE id=%s",
                    (stato, riga["id"]))
    return {
        "ok": True,
        "message": f"Comando {nome_azione} inviato a {riga['name']}",
        "power_state": stato,
    }


def _power_bmc(cur, riga, azione):
    from app import bmc_collector
    try:
        stato, comando = bmc_collector.accensione(riga, azione)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"La scheda ha rifiutato l'azione: {exc}")
    if stato:
        cur.execute("UPDATE servers SET power_state=%s WHERE id=%s",
                    (stato, riga["id"]))
    return {
        "ok": True,
        "message": f"Comando {comando} inviato a {riga['name']}",
        "power_state": stato,
    }


@app.post("/api/servers/{server_id}/led")
def toggle_led(server_id: int):
    """Accende o spegne il LED di identificazione (UID)."""
    con = db()
    try:
        with con.cursor() as cur:
            riga = one(cur, "SELECT * FROM servers WHERE id=%s", (server_id,))
            if riga and riga.get("ilo_protocol") == "ribcl":
                from app import ribcl_collector
                try:
                    target = ribcl_collector.led_uid(riga)
                except Exception as exc:
                    raise HTTPException(502, f"iLO ha rifiutato l'azione: {exc}")
                cur.execute("UPDATE servers SET indicator_led=%s WHERE id=%s",
                            (target, server_id))
                return {"ok": True, "indicator_led": target}
            if riga and riga.get("ilo_protocol") == "bmc":
                from app import bmc_collector
                try:
                    target = bmc_collector.led(riga)
                except Exception as exc:
                    raise HTTPException(
                        502, f"La scheda ha rifiutato l'azione: {exc}")
                cur.execute("UPDATE servers SET indicator_led=%s WHERE id=%s",
                            (target, server_id))
                return {"ok": True, "indicator_led": target}
            row, rf = _open_session(cur, server_id)
            try:
                current = rf.get("/Systems/1/").get("IndicatorLED")
                target = "Off" if str(current).lower() == "lit" else "Lit"
                rf.patch("/Systems/1/", {"IndicatorLED": target})
                cur.execute(
                    "UPDATE servers SET indicator_led=%s WHERE id=%s",
                    (target, server_id),
                )
            except Exception as exc:
                raise HTTPException(502, f"iLO ha rifiutato l'azione: {exc}")
            finally:
                rf.close()
            return {"ok": True, "indicator_led": target}
    finally:
        con.close()


# ================================================================
# SCRIPT PER WINDOWS: DISCHI E SMART DAL SISTEMA OPERATIVO
# ================================================================
# L'iLO non vede tutto: gli iLO 2 non conoscono gli NVMe su scheda
# PCIe, e senza Agentless Management nemmeno gli iLO 5 vedono i dischi
# sul SATA integrato. Windows invece li vede tutti, con i contatori
# SMART. Lo script, generato qui per un server preciso, li legge e li
# invia; si autentica con una chiave sua, di cui conserviamo solo
# l'impronta.

TIPI_BUS_NVME = {"nvme"}


def _impronta(chiave):
    return hashlib.sha256(chiave.encode("utf-8")).hexdigest()


@app.get("/api/servers/{server_id}/agent-script")
def agent_script(server_id: int, request: Request):
    """Genera lo script per Windows del server. Ogni generazione crea
    una chiave nuova e invalida quella dello script precedente."""
    con = db()
    try:
        with con.cursor() as cur:
            row = one(cur, "SELECT id, name, ilo_protocol FROM servers "
                      "WHERE id=%s", (server_id,))
            if not row:
                raise HTTPException(404, "Server non trovato")
            chiave = secrets.token_urlsafe(32)
            cur.execute(
                "UPDATE servers SET agent_token_hash=%s WHERE id=%s",
                (_impronta(chiave), server_id),
            )
    finally:
        con.close()

    # L'indirizzo che il browser sta usando e' quello che il server
    # Windows deve raggiungere: nginx lo passa nell'intestazione Host.
    schema = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    pannello = f"{schema}://{host}" if host else str(request.base_url).rstrip("/")

    nome_file = "ilo-monitor-dischi-" + re.sub(
        r"[^A-Za-z0-9_-]", "_", row["name"])[:40] + ".ps1"
    with open(os.path.join(os.path.dirname(__file__), "agent_dischi.ps1"),
              encoding="utf-8") as fh:
        testo = fh.read()
    testo = (testo.replace("{{URL}}", pannello)
                  .replace("{{TOKEN}}", chiave)
                  .replace("{{NOME}}", row["name"].replace("'", ""))
                  .replace("{{FILE}}", nome_file)
                  # I sensori li chiediamo solo dove nessun altro li legge:
                  # le schede di gestione generiche (gli iLO li leggono gia').
                  .replace("{{SENSORI}}",
                           "1" if row.get("ilo_protocol") == "bmc" else "0")
                  .replace("{{DATA}}", datetime.now().strftime("%d/%m/%Y %H:%M")))
    # BOM UTF-8 e fine riga Windows: PowerShell 5 legge cosi' senza
    # sorprese anche gli accenti nei nomi dei server.
    corpo = "﻿" + testo.replace("\r\n", "\n").replace("\n", "\r\n")
    return Response(
        content=corpo.encode("utf-8"),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{nome_file}"',
            "Cache-Control": "no-store",
        },
    )


def _intero(v):
    try:
        if v is None or v == "":
            return None
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _decimale(v):
    try:
        if v is None or v == "":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


# Attributi SMART ATA che indicano la vita residua (valore normalizzato,
# 100 = nuovo), nell'ordine in cui li cerchiamo:
#   231 SSD Life Left (Kingston, SandForce), 233 Media Wearout Indicator
#   (Intel), 202 Percent Lifetime Remaining (Micron, Crucial),
#   177 Wear Leveling Count (Samsung), 169 Remaining Life (vari).
ATA_VITA = (231, 233, 202, 177, 169)
ATA_NOMI = {
    5: "Settori riallocati", 9: "Ore di accensione", 12: "Cicli di accensione",
    177: "Wear leveling", 187: "Errori non correggibili riportati",
    194: "Temperatura", 190: "Temperatura (flusso d'aria)",
    196: "Eventi di riallocazione", 197: "Settori in attesa",
    198: "Settori non correggibili", 199: "Errori CRC interfaccia",
    202: "Vita residua %", 231: "Vita residua SSD", 233: "Indicatore di usura",
    241: "Dati scritti (LBA)", 242: "Dati letti (LBA)",
}


def ore_e_anni(ore):
    """44844 -> '44844 (5,1 anni)': le ore restano, gli anni si leggono."""
    n = _intero(ore)
    if n is None:
        return ore
    if n < 8760:
        return str(n)
    return f"{n} ({n / 8760:.1f} anni)".replace(".", ",")


def interpreta_smart(d, bus, tipo):
    """Dai contatori grezzi dello script ai valori del pannello.

    Restituisce un dizionario con vita, usura, ore, temperatura, errori,
    guasto previsto e le righe leggibili per il dettaglio.
    """
    esito = {"vita": None, "usura": None, "ore": None, "temperatura": None,
             "errori": None, "guasto": None, "salute": None, "righe": []}
    righe = esito["righe"]

    nvme = d.get("nvme") if isinstance(d.get("nvme"), dict) else None
    ata = d.get("ata") if isinstance(d.get("ata"), list) else None
    if isinstance(d.get("ata"), dict):
        ata = [d["ata"]]

    if nvme and nvme.get("percentuale_usata") is not None:
        usata = _intero(nvme.get("percentuale_usata"))
        # Lo standard NVMe permette valori oltre 100: durata nominale
        # superata, vita residua zero (non un dato da scartare).
        esito["usura"] = usata
        esito["vita"] = max(0, 100 - usata) if usata is not None else None
        esito["ore"] = _intero(nvme.get("ore_accensione"))
        kelvin = _intero(nvme.get("temperatura_kelvin"))
        if kelvin and kelvin > 200:
            esito["temperatura"] = kelvin - 273
        esito["errori"] = _intero(nvme.get("errori_supporto"))
        avviso = _intero(nvme.get("avviso_critico")) or 0
        riserva = _intero(nvme.get("riserva"))
        soglia = _intero(nvme.get("riserva_soglia"))
        if avviso:
            esito["guasto"] = True
            esito["salute"] = "Critical"
        elif riserva is not None and soglia is not None and riserva < soglia:
            esito["salute"] = "Warning"
        gb = lambda u: round((_intero(u) or 0) * 512000 / 1e12, 2)
        righe += [
            ("Usura (Percentage Used)", f"{usata}%"),
            ("Riserva disponibile", f"{riserva}% (soglia {soglia}%)"),
            ("Dati scritti", f"{gb(nvme.get('unita_scritte'))} TB"),
            ("Dati letti", f"{gb(nvme.get('unita_lette'))} TB"),
            ("Ore di accensione", ore_e_anni(nvme.get("ore_accensione"))),
            ("Cicli di accensione", nvme.get("cicli_accensione")),
            ("Spegnimenti anomali", nvme.get("spegnimenti_anomali")),
            ("Errori del supporto", nvme.get("errori_supporto")),
            ("Voci nel registro errori", nvme.get("voci_registro_errori")),
            ("Avviso critico", "nessuno" if not avviso else f"codice {avviso}"),
        ]

    elif ata:
        attr = {}
        for a in ata:
            if isinstance(a, dict) and _intero(a.get("id")):
                attr[_intero(a["id"])] = a
        if tipo != "HDD":
            for codice in ATA_VITA:
                a = attr.get(codice)
                v = _intero(a.get("valore")) if a else None
                if v is not None and 0 < v <= 100:
                    esito["vita"] = v
                    esito["usura"] = 100 - v
                    break
        if 9 in attr:
            esito["ore"] = (_intero(attr[9].get("grezzo")) or 0) & 0xFFFFFFFF
        for codice in (194, 190):
            if codice in attr:
                t = (_intero(attr[codice].get("grezzo")) or 0) & 0xFF
                if 0 < t < 120:
                    esito["temperatura"] = t
                    break
        errori = [(_intero(attr[c].get("grezzo")) or 0) & 0xFFFFFFFF
                  for c in (187, 198) if c in attr]
        if errori:
            esito["errori"] = sum(errori)
        if (_intero((attr.get(197) or {}).get("grezzo")) or 0) & 0xFFFFFFFF:
            esito["salute"] = "Warning"
        if 241 in attr:
            # Samsung, Kingston e molti altri contano blocchi da 512 byte.
            scritti = (_intero(attr[241].get("grezzo")) or 0) * 512 / 1e12
            if 0 < scritti < 10000:
                righe.append(("Dati scritti (stima)", f"{scritti:.2f} TB"))
        if esito["ore"] is not None:
            righe.append(("Ore di accensione", ore_e_anni(esito["ore"])))
        for codice in sorted(attr):
            a = attr[codice]
            nome = ATA_NOMI.get(codice, f"Attributo {codice}")
            righe.append((f"{codice} {nome}",
                          f"valore {a.get('valore')}, peggiore {a.get('peggiore')}, "
                          f"grezzo {a.get('grezzo')}"))

    if d.get("previsione_guasto") is True:
        esito["guasto"] = True
        esito["salute"] = "Critical"

    # Ripiego sui contatori di Windows dove la lettura diretta non c'e'.
    if esito["ore"] is None:
        esito["ore"] = _intero(d.get("ore_accensione"))
    if esito["temperatura"] is None:
        t = _decimale(d.get("temperatura"))
        esito["temperatura"] = t if t and t > 0 else None
    if esito["errori"] is None:
        e = [_intero(d.get("errori_lettura")), _intero(d.get("errori_scrittura"))]
        if any(x is not None for x in e):
            esito["errori"] = sum(x for x in e if x is not None)
    if esito["vita"] is None:
        usura = _decimale(d.get("usura"))
        # Il "Wear" di Windows: preso solo se diverso da 0 (0 di solito
        # vuol dire "non lo so", non "disco nuovo").
        if usura:
            esito["usura"] = usura
            esito["vita"] = collector.life_left(usura, consumed=True)

    righe += [(nome, d.get(chiave)) for nome, chiave in (
        ("Temperatura massima (Windows)", "temperatura_max"),
        ("Errori di lettura corretti", "errori_lettura_corretti"),
        ("Errori di scrittura corretti", "errori_scrittura_corretti"),
        ("Latenza lettura max ms", "latenza_lettura_max_ms"),
        ("Latenza scrittura max ms", "latenza_scrittura_max_ms"),
        ("Firmware", "firmware"), ("Collegamento", "bus"),
        ("Posizione", "posizione"),
    ) if d.get(chiave) not in (None, "", 0)]
    esito["righe"] = [[str(a), str(b)] for a, b in righe if b not in (None, "")]
    return esito


def _posizione(testo, numero):
    t = str(testo or "")
    m = re.search(r"Slot\s*(\d+)", t, re.I)
    if m:
        return f"Slot PCIe {m.group(1)}"
    return f"Disco {numero}" if numero not in (None, "") else "Disco"


# Soglie per i sensori letti da Windows, che non ne riportano:
# (attenzione, critica) per famiglia di componente.
SOGLIE_SENSORI = {
    "Cpu": (85, 100),
    "Motherboard": (70, 85),
    "SuperIO": (70, 85),
    "Memory": (70, 85),
    "GpuNvidia": (85, 95),
    "GpuAmd": (85, 95),
    "GpuIntel": (85, 95),
}
NOMI_GRUPPI = {
    "Cpu": "CPU", "Motherboard": "Scheda madre", "SuperIO": "Scheda madre",
    "Memory": "Memoria", "GpuNvidia": "GPU", "GpuAmd": "GPU",
    "GpuIntel": "GPU", "Psu": "Alimentatore",
}


def _salva_sensori(cur, server_id, sensori, adesso):
    """Temperature, ventole e carico inviati dallo script Windows
    (LibreHardwareMonitor). Restituisce quanti sensori ha salvato."""
    salvati = 0
    temperature = sensori.get("temperature") or []
    if isinstance(temperature, dict):
        temperature = [temperature]
    visti = set()
    n = 0
    for t in temperature[:60]:
        if not isinstance(t, dict):
            continue
        valore = _decimale(t.get("valore"))
        if valore is None or not (-40 < valore < 150):
            continue
        gruppo = str(t.get("gruppo") or "")
        nome = str(t.get("nome") or "").strip() or "Sensore"
        # LibreHardwareMonitor espone come temperature anche le soglie
        # scritte nei moduli di memoria ("Thermal Sensor High Limit"):
        # non sono letture.
        if re.search(r"limit|threshold|resolution", nome, re.I):
            continue
        etichetta = f"{NOMI_GRUPPI.get(gruppo, gruppo or 'Sistema')} {nome}"
        if nome.lower().startswith(NOMI_GRUPPI.get(gruppo, "").lower() + " ") \
                or (gruppo == "Cpu" and nome.upper().startswith("CPU")):
            etichetta = nome
        if etichetta in visti:
            continue
        visti.add(etichetta)
        n += 1
        attenzione, critica = SOGLIE_SENSORI.get(gruppo, (None, None))
        if "cpu" in nome.lower():
            # Anche la sonda della scheda madre vicino al processore
            # segue i limiti del processore.
            attenzione, critica = SOGLIE_SENSORI["Cpu"]
        cur.execute(
            """
            INSERT INTO thermal_sensors
            (server_id, collected_at, sensor_name, sensor_number,
             temperature_c, health, state, warning_threshold,
             critical_threshold, fatal_threshold)
            VALUES (%s,%s,%s,%s,%s,%s,'Enabled',%s,%s,NULL)
            """,
            (server_id, adesso, f"{n:02d}-{etichetta}"[:255],
             str(t.get("componente") or "")[:100] or None, valore,
             "Critical" if critica and valore >= critica
             else "Warning" if attenzione and valore >= attenzione else "OK",
             attenzione, critica),
        )
        salvati += 1

    ventole = sensori.get("ventole") or []
    if isinstance(ventole, dict):
        ventole = [ventole]
    for n, v in enumerate([x for x in ventole if isinstance(x, dict)][:30],
                          start=1):
        giri = _intero(v.get("giri"))
        if giri is None or giri <= 0 or giri > 30000:
            continue
        gruppo = str(v.get("gruppo") or "")
        nome = str(v.get("nome") or "").strip() or f"Ventola {n}"
        if gruppo.startswith("Gpu"):
            nome = f"GPU {nome}"
        cur.execute(
            """
            INSERT INTO fans
            (server_id, collected_at, fan_id, fan_name, status, health,
             state, speed_percent, speed_rpm)
            VALUES (%s,%s,%s,%s,NULL,'OK','Enabled',NULL,%s)
            """,
            (server_id, adesso, f"os-{n}", nome[:255], giri),
        )
        salvati += 1

    carico = _decimale(sensori.get("carico_cpu"))
    memoria = _decimale(sensori.get("memoria"))
    potenza = _decimale(sensori.get("potenza_cpu"))
    if carico is not None or memoria is not None:
        cur.execute(
            """
            INSERT INTO system_metrics
            (server_id, collected_at, cpu_utilization, cpu_power_watts,
             memory_utilization, memory_power_watts, io_bus_utilization,
             memory_bus_utilization, ambient_temperature)
            VALUES (%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL)
            """,
            (server_id, adesso, carico, potenza, memoria),
        )
    if potenza is not None and potenza > 0:
        cur.execute(
            "INSERT INTO power_metrics (server_id, collected_at, cpu_watts) "
            "VALUES (%s,%s,%s)",
            (server_id, adesso, potenza),
        )
    return salvati


def _salva_inventario(cur, server_id, inv, adesso):
    """Inventario letto da Windows, per i server la cui scheda di
    gestione non lo conosce (BMC generici)."""
    def testo(v, n=255):
        v = str(v or "").strip()
        return v[:n] or None

    processori = [p for p in (inv.get("processori") or []) if isinstance(p, dict)] \
        if not isinstance(inv.get("processori"), dict) else [inv["processori"]]
    memoria = [m for m in (inv.get("memoria") or []) if isinstance(m, dict)] \
        if not isinstance(inv.get("memoria"), dict) else [inv["memoria"]]
    totale_mib = sum(_intero(m.get("mib")) or 0 for m in memoria)
    avvio = None
    try:
        avvio = datetime.fromisoformat(str(inv.get("avvio") or "")[:19])
    except ValueError:
        pass
    cur.execute(
        """
        UPDATE servers SET
            hostname=COALESCE(%s, hostname),
            manufacturer=COALESCE(%s, manufacturer),
            model=COALESCE(%s, model),
            serial_number=COALESCE(%s, serial_number),
            bios_version=COALESCE(%s, bios_version),
            host_os=COALESCE(%s, host_os),
            last_boot_at=COALESCE(%s, last_boot_at),
            processor_summary=%s, processor_count=%s, core_count=%s,
            memory_total_gib=%s
        WHERE id=%s
        """,
        (
            testo(inv.get("hostname")), testo(inv.get("produttore"), 100),
            testo(inv.get("modello")), testo(inv.get("seriale"), 100),
            testo(inv.get("bios"), 100), testo(inv.get("so")), avvio,
            testo(processori[0].get("modello")) if processori else None,
            len(processori) or None,
            sum(_intero(p.get("core")) or 0 for p in processori) or None,
            round(totale_mib / 1024, 2) if totale_mib else None,
            server_id,
        ),
    )
    for n, p in enumerate(processori[:8], start=1):
        cur.execute(
            """
            INSERT INTO processors
            (server_id, collected_at, processor_id, socket, model,
             manufacturer, max_speed_mhz, total_cores, total_threads,
             health, state)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,'Enabled')
            """,
            (server_id, adesso, f"cpu-{n}", testo(p.get("socket"), 100),
             testo(p.get("modello")), testo(p.get("produttore"), 100),
             _intero(p.get("mhz")), _intero(p.get("core")),
             _intero(p.get("thread"))),
        )
    for n, m in enumerate(memoria[:64], start=1):
        cur.execute(
            """
            INSERT INTO memory_modules
            (server_id, collected_at, dimm_id, device_locator, capacity_mib,
             speed_mhz, memory_type, manufacturer, part_number, rank_count,
             health, state)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,NULL,'Enabled')
            """,
            (server_id, adesso, f"dimm-{n}", testo(m.get("posizione"), 150),
             _intero(m.get("mib")), _intero(m.get("mhz")),
             testo(m.get("tipo"), 50), testo(m.get("produttore"), 100),
             testo(m.get("codice"), 150)),
        )


@app.post("/api/agent/drives")
async def agent_drives(request: Request):
    autorizzazione = request.headers.get("authorization") or ""
    if not autorizzazione.lower().startswith("bearer "):
        raise HTTPException(401, "Chiave mancante")
    chiave = autorizzazione[7:].strip()
    if len(chiave) < 20:
        raise HTTPException(401, "Chiave non valida")

    try:
        dati = await request.json()
    except Exception:
        raise HTTPException(400, "Corpo della richiesta non valido")
    dischi = dati.get("dischi") or []
    if isinstance(dischi, dict):
        dischi = [dischi]
    if not isinstance(dischi, list) or len(dischi) > 128:
        raise HTTPException(400, "Elenco dei dischi non valido")

    con = db()
    try:
        with con.cursor() as cur:
            row = one(
                cur,
                "SELECT id, name, ilo_protocol FROM servers "
                "WHERE agent_token_hash=%s",
                (_impronta(chiave),),
            )
            if not row:
                raise HTTPException(
                    401, "Chiave non riconosciuta: rigenera lo script dal pannello")
            server_id = row["id"]
            adesso = collector.now()
            salvati = 0
            for n, d in enumerate(dischi, start=1):
                if not isinstance(d, dict):
                    continue
                bus = str(d.get("bus") or "").strip()
                tipo = str(d.get("tipo") or "").strip().upper()
                if tipo not in ("SSD", "HDD", "SCM"):
                    tipo = "SSD" if bus.lower() in TIPI_BUS_NVME else None
                smart = interpreta_smart(d, bus, tipo)
                giri = _intero(d.get("giri"))
                if giri is not None and not (0 < giri < 100000):
                    giri = None
                salute = {"healthy": "OK", "warning": "Warning",
                          "unhealthy": "Critical"}.get(
                    str(d.get("salute") or "").strip().lower())
                # Il peggiore fra il giudizio di Windows e quello SMART.
                ordine = {None: 0, "OK": 1, "Warning": 2, "Critical": 3}
                if ordine.get(smart["salute"], 0) > ordine.get(salute, 0):
                    salute = smart["salute"]
                seriale = str(d.get("seriale") or "").strip() or None
                cur.execute(
                    """
                    INSERT INTO physical_drives
                    (server_id, collected_at, drive_id, bay, manufacturer,
                     model, revision, protocol, media_type, capacity_bytes,
                     rotation_rpm, negotiated_speed_gbs, health, state,
                     failure_predicted, media_life_left_percent, serial_number,
                     endurance_used_percent, power_on_hours, source,
                     temperature_c, uncorrected_errors, smart_json)
                    VALUES (%s,%s,%s,%s,NULL,%s,%s,%s,%s,%s,%s,NULL,%s,%s,
                            %s,%s,%s,%s,%s,'os',%s,%s,%s)
                    """,
                    (
                        server_id, adesso,
                        ("os-" + (seriale or str(d.get("numero") or n)))[:100],
                        _posizione(d.get("posizione"), d.get("numero"))[:100],
                        (str(d.get("modello") or "").strip() or None),
                        (str(d.get("firmware") or "").strip() or None),
                        bus or None, tipo,
                        _intero(d.get("dimensione")),
                        giri, salute, "Enabled",
                        smart["guasto"], smart["vita"], seriale, smart["usura"],
                        smart["ore"], smart["temperatura"], smart["errori"],
                        json.dumps({"righe": smart["righe"]}, ensure_ascii=False),
                    ),
                )
                salvati += 1
            n_sensori = 0
            nota = None
            sensori = dati.get("sensori")
            if row.get("ilo_protocol") == "bmc":
                if isinstance(sensori, dict):
                    n_sensori = _salva_sensori(cur, server_id, sensori, adesso)
                    if not sensori.get("pawnio"):
                        nota = ("driver PawnIO non installato: CPU e scheda "
                                "madre non si leggono")
                    elif not n_sensori:
                        nota = "nessun sensore letto"
                elif dati.get("errore_sensori"):
                    nota = str(dati.get("errore_sensori"))[:250]
                if isinstance(dati.get("inventario"), dict):
                    _salva_inventario(cur, server_id, dati["inventario"], adesso)
            cur.execute(
                "UPDATE servers SET agent_last_at=%s, agent_host=%s, "
                "agent_sensors_note=%s WHERE id=%s",
                (adesso, str(dati.get("host") or "")[:255] or None,
                 nota, server_id),
            )
            return {"ok": True, "server": row["name"], "salvati": salvati,
                    "sensori": n_sensori}
    finally:
        con.close()


# ================================================================
# EVENTI GLOBALI
# ================================================================


@app.get("/api/events")
def events(
    server_id: Optional[int] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    hours: int = Query(168, ge=1, le=8760),
    q: Optional[str] = None,
    limit: int = Query(300, ge=1, le=2000),
):
    con = db()
    try:
        with con.cursor() as cur:
            sql = """
                SELECT e.*, s.name AS server_name, s.ilo_ip
                FROM ilo_events e
                JOIN servers s ON s.id=e.server_id
                WHERE e.event_created >= NOW() - INTERVAL %s HOUR
            """
            args = [hours]
            if server_id:
                sql += " AND e.server_id=%s"
                args.append(server_id)
            if severity and severity.lower() != "all":
                if severity.lower() == "informational":
                    sql += (
                        " AND (e.severity IS NULL OR UPPER(e.severity) NOT IN "
                        "('WARNING','CRITICAL','FATAL'))"
                    )
                else:
                    sql += " AND UPPER(e.severity)=%s"
                    args.append(severity.upper())
            if source and source.lower() != "all":
                sql += " AND e.log_source=%s"
                args.append(source.upper())
            if q:
                sql += " AND (e.message LIKE %s OR e.message_id LIKE %s)"
                args.extend([f"%{q}%", f"%{q}%"])
            sql += " ORDER BY e.event_created DESC, e.id DESC LIMIT %s"
            args.append(limit)
            return {"ok": True, "data": many(cur, sql, args)}
    finally:
        con.close()


@app.get("/api/event-sources")
def event_sources():
    """Log effettivamente presenti in archivio, con il conteggio.

    Quali log un iLO esponga dipende da generazione e firmware
    (IEL, IML, SL, EVENT...), quindi l'elenco lo ricaviamo dai dati
    invece di fissarlo nell'interfaccia.
    """
    con = db()
    try:
        with con.cursor() as cur:
            return {
                "ok": True,
                "data": many(
                    cur,
                    """
                    SELECT log_source, COUNT(*) AS total
                    FROM ilo_events
                    GROUP BY log_source
                    ORDER BY total DESC
                    """,
                ),
            }
    finally:
        con.close()


# ================================================================
# MAPPE TERMICHE
# ================================================================


@app.get("/api/thermal")
def thermal_map():
    """Ultima lettura di tutti i sensori di tutti i server abilitati."""
    con = db()
    try:
        with con.cursor() as cur:
            settings = get_settings_dict(cur)
            rows = many(
                cur,
                """
                SELECT t.*, s.name AS server_name, s.ilo_ip, s.model
                FROM thermal_sensors t
                JOIN servers s ON s.id=t.server_id
                JOIN (
                    SELECT ts.server_id, ts.sensor_name, ts.sensor_number,
                           MAX(ts.id) AS id
                    FROM thermal_sensors ts
                    JOIN (
                        SELECT server_id, MAX(collected_at) AS ultimo
                        FROM thermal_sensors GROUP BY server_id
                    ) u ON u.server_id=ts.server_id
                       AND u.ultimo=ts.collected_at
                    GROUP BY ts.server_id, ts.sensor_name, ts.sensor_number
                ) x ON x.id=t.id
                WHERE s.enabled=1
                ORDER BY s.name, t.temperature_c DESC
                """,
            )
            fans = many(
                cur,
                """
                SELECT f.*, s.name AS server_name
                FROM fans f
                JOIN servers s ON s.id=f.server_id
                JOIN (
                    SELECT fs.server_id, fs.fan_id, MAX(fs.id) AS id
                    FROM fans fs
                    JOIN (
                        SELECT server_id, MAX(collected_at) AS ultimo
                        FROM fans GROUP BY server_id
                    ) u ON u.server_id=fs.server_id
                       AND u.ultimo=fs.collected_at
                    GROUP BY fs.server_id, fs.fan_id
                ) x ON x.id=f.id
                WHERE s.enabled=1
                ORDER BY s.name, f.fan_id
                """,
            )
            return {
                "ok": True,
                "data": {
                    "sensors": rows,
                    "fans": fans,
                    "temp_warning_c": float(
                        settings.get("temp_warning_c", 55)
                    ),
                    "temp_critical_c": float(
                        settings.get("temp_critical_c", 70)
                    ),
                },
            }
    finally:
        con.close()


# ================================================================
# DISCHI FISICI DI TUTTI I SERVER
# ================================================================


@app.get("/api/drives")
def drives_overview():
    """Ultimo inventario dei dischi di ogni server abilitato.

    Ordinati per vita residua crescente: i dischi da tenere d'occhio
    vengono per primi, quelli che non la riportano (HDD) in fondo.
    """
    con = db()
    try:
        with con.cursor() as cur:
            server = many(
                cur,
                "SELECT id, name, ilo_ip, model FROM servers "
                "WHERE enabled=1 ORDER BY name",
            )
            rows = []
            for srv in server:
                for d in ultimi_dischi(cur, srv["id"]):
                    d["server_name"] = srv["name"]
                    d["ilo_ip"] = srv["ilo_ip"]
                    d["server_model"] = srv["model"]
                    rows.append(d)

            def ordine(d):
                vita = d.get("media_life_left_percent")
                return (vita is None, float(vita) if vita is not None else 0,
                        str(d["server_name"]), str(d.get("bay") or ""))

            rows.sort(key=ordine)
            senza = many(
                cur,
                """
                SELECT s.id, s.name, s.ilo_ip
                FROM servers s
                WHERE s.enabled=1
                  AND NOT EXISTS (
                      SELECT 1 FROM physical_drives d WHERE d.server_id=s.id
                  )
                ORDER BY s.name
                """,
            )
            return {
                "ok": True,
                "data": {
                    "drives": rows,
                    "servers_without_data": senza,
                    "life_warning": 30,
                    "life_critical": 10,
                },
            }
    finally:
        con.close()


# ================================================================
# REPORT
# ================================================================


@app.get("/api/reports")
def reports(hours: int = Query(24, ge=1, le=8760)):
    """Serie storiche aggregate per tutti i server abilitati."""
    con = db()
    try:
        with con.cursor() as cur:
            servers_rows = many(
                cur,
                "SELECT id, name, model FROM servers "
                "WHERE enabled=1 ORDER BY name",
            )

            # I segnaposto di DATE_FORMAT vanno raddoppiati: la query
            # viene passata con parametri, e pymysql interpreta ogni %
            # come proprio segnaposto prima di inviarla al database.
            bucket = (
                "%%Y-%%m-%%d %%H:00:00" if hours > 48
                else "%%Y-%%m-%%d %%H:%%i:00"
            )

            power = many(
                cur,
                f"""
                SELECT server_id,
                       DATE_FORMAT(collected_at, '{bucket}') AS bucket,
                       AVG(consumed_watts) AS watts
                FROM power_metrics
                WHERE collected_at >= NOW() - INTERVAL %s HOUR
                GROUP BY server_id, bucket
                ORDER BY bucket
                """,
                (hours,),
            )
            temperature = many(
                cur,
                f"""
                SELECT server_id,
                       DATE_FORMAT(collected_at, '{bucket}') AS bucket,
                       MAX(temperature_c) AS temp
                FROM thermal_sensors
                WHERE collected_at >= NOW() - INTERVAL %s HOUR
                GROUP BY server_id, bucket
                ORDER BY bucket
                """,
                (hours,),
            )
            cpu = many(
                cur,
                f"""
                SELECT server_id,
                       DATE_FORMAT(collected_at, '{bucket}') AS bucket,
                       AVG(cpu_utilization) AS cpu
                FROM system_metrics
                WHERE collected_at >= NOW() - INTERVAL %s HOUR
                GROUP BY server_id, bucket
                ORDER BY bucket
                """,
                (hours,),
            )
            totals = many(
                cur,
                """
                SELECT s.id AS server_id, s.name,
                       AVG(p.consumed_watts) AS avg_watts,
                       MAX(p.consumed_watts) AS max_watts,
                       MIN(p.consumed_watts) AS min_watts,
                       COUNT(p.id) AS samples
                FROM servers s
                LEFT JOIN power_metrics p
                       ON p.server_id=s.id
                      AND p.collected_at >= NOW() - INTERVAL %s HOUR
                WHERE s.enabled=1
                GROUP BY s.id, s.name
                ORDER BY s.name
                """,
                (hours,),
            )
            events_by_day = many(
                cur,
                """
                SELECT DATE(event_created) AS day,
                       COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(severity) IN ('CRITICAL','FATAL')
                                THEN 1 ELSE 0 END) AS critical,
                       SUM(CASE WHEN UPPER(severity)='WARNING'
                                THEN 1 ELSE 0 END) AS warning
                FROM ilo_events
                WHERE event_created >= NOW() - INTERVAL %s HOUR
                GROUP BY day
                ORDER BY day
                """,
                (hours,),
            )
            return {
                "ok": True,
                "data": {
                    "servers": servers_rows,
                    "power": power,
                    "temperature": temperature,
                    "cpu": cpu,
                    "totals": totals,
                    "events_by_day": events_by_day,
                    "hours": hours,
                },
            }
    finally:
        con.close()


# ================================================================
# IMPOSTAZIONI
# ================================================================


def get_settings_dict(cur):
    rows = many(cur, "SELECT setting_key, setting_value FROM settings")
    return {r["setting_key"]: r["setting_value"] for r in rows}


@app.get("/api/settings")
def read_settings():
    con = db()
    try:
        with con.cursor() as cur:
            values = get_settings_dict(cur)
            runs = many(
                cur,
                """
                SELECT r.*, s.name AS server_name
                FROM collection_runs r
                JOIN servers s ON s.id=r.server_id
                ORDER BY r.id DESC LIMIT 15
                """,
            )
            counts = one(
                cur,
                """
                SELECT
                    (SELECT COUNT(*) FROM servers) AS servers,
                    (SELECT COUNT(*) FROM servers WHERE enabled=1)
                        AS servers_enabled,
                    (SELECT COUNT(*) FROM ilo_events) AS events,
                    (SELECT COUNT(*) FROM system_metrics) AS metrics,
                    (SELECT MIN(collected_at) FROM system_metrics)
                        AS oldest_metric
                """,
            )
            return {
                "ok": True,
                "data": {
                    "settings": values,
                    "runs": runs,
                    "counts": counts,
                    "database": f"{DB_NAME} @ {DB_HOST}:{DB_PORT}",
                },
            }
    finally:
        con.close()


@app.put("/api/settings")
def write_settings(payload: SettingsIn):
    values = {
        k: v for k, v in payload.model_dump().items() if v is not None
    }
    if not values:
        raise HTTPException(400, "Nessuna impostazione da salvare")

    con = db()
    try:
        with con.cursor() as cur:
            for key, value in values.items():
                cur.execute(
                    """
                    INSERT INTO settings (setting_key, setting_value)
                    VALUES (%s,%s)
                    ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)
                    """,
                    (key, str(value)),
                )
            return {"ok": True, "data": get_settings_dict(cur)}
    finally:
        con.close()


# ================================================================
# AVVISI EMAIL
# ================================================================

CAMPI_REGOLA = [
    "enabled", "cat_storage", "cat_fans", "cat_thermal", "cat_power",
    "cat_memory", "cat_cpu", "cat_network", "cat_other",
    "alert_temperature", "alert_drives", "alert_psu_fans",
    "alert_unreachable",
]

SEVERITA_AMMESSE = {"Informational", "Warning", "Critical"}


@app.get("/api/alerts")
def read_alerts():
    """Configurazione SMTP e regole per server."""
    con = db()
    try:
        with con.cursor() as cur:
            valori = get_settings_dict(cur)

            # Sola lettura: i server senza riga mostrano i valori
            # predefiniti, e la riga nasce alla prima modifica. Una
            # scrittura qui prenderebbe un lock su `servers`, che il
            # collector tiene occupata per tutta la raccolta, e la
            # pagina resterebbe in attesa.
            regole = many(
                cur,
                """
                SELECT
                    s.id AS server_id,
                    s.name, s.ilo_ip, s.model,
                    s.enabled AS server_enabled,
                    COALESCE(a.enabled, 1) AS enabled,
                    COALESCE(a.min_severity, 'Critical') AS min_severity,
                    COALESCE(a.cat_storage, 1) AS cat_storage,
                    COALESCE(a.cat_fans, 1) AS cat_fans,
                    COALESCE(a.cat_thermal, 1) AS cat_thermal,
                    COALESCE(a.cat_power, 1) AS cat_power,
                    COALESCE(a.cat_memory, 1) AS cat_memory,
                    COALESCE(a.cat_cpu, 1) AS cat_cpu,
                    COALESCE(a.cat_network, 0) AS cat_network,
                    COALESCE(a.cat_other, 0) AS cat_other,
                    COALESCE(a.alert_temperature, 1) AS alert_temperature,
                    COALESCE(a.alert_drives, 1) AS alert_drives,
                    COALESCE(a.alert_psu_fans, 1) AS alert_psu_fans,
                    COALESCE(a.alert_unreachable, 1) AS alert_unreachable,
                    a.last_alert_at,
                    (a.server_id IS NOT NULL) AS configurato
                FROM servers s
                LEFT JOIN server_alerts a ON a.server_id = s.id
                ORDER BY s.name
                """,
            )
            invii = many(
                cur,
                """
                SELECT l.id, l.sent_at, l.subject, l.recipients, l.status,
                       l.error_message, s.name AS server_name
                FROM alert_log l
                LEFT JOIN servers s ON s.id = l.server_id
                ORDER BY l.id DESC LIMIT 20
                """,
            )
            return {
                "ok": True,
                "data": {
                    "smtp": {
                        "smtp_enabled": valori.get("smtp_enabled", "0"),
                        "smtp_host": valori.get("smtp_host", ""),
                        "smtp_port": valori.get("smtp_port", "587"),
                        "smtp_security": valori.get("smtp_security", "starttls"),
                        "smtp_user": valori.get("smtp_user", ""),
                        "smtp_from": valori.get("smtp_from", ""),
                        "smtp_to": valori.get("smtp_to", ""),
                        "alert_max_per_run": valori.get("alert_max_per_run", "10"),
                        # La password non torna mai al browser: diciamo
                        # soltanto se ce n'e' una salvata.
                        "has_password": bool(valori.get("smtp_password_enc")),
                    },
                    "rules": regole,
                    "recent": invii,
                },
            }
    finally:
        con.close()


@app.put("/api/alerts/smtp")
def write_smtp(payload: SmtpIn):
    valori = payload.model_dump(exclude_none=True)
    password = valori.pop("smtp_password", None)

    if valori.get("smtp_security") and valori["smtp_security"] not in (
        "none", "starttls", "ssl"
    ):
        raise HTTPException(400, "Modalita' di cifratura non valida")

    con = db()
    try:
        with con.cursor() as cur:
            for chiave, valore in valori.items():
                cur.execute(
                    """
                    INSERT INTO settings (setting_key, setting_value)
                    VALUES (%s,%s)
                    ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)
                    """,
                    (chiave, str(valore)),
                )
            if password:
                cur.execute(
                    """
                    INSERT INTO settings (setting_key, setting_value)
                    VALUES ('smtp_password_enc', %s)
                    ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)
                    """,
                    (encrypt(password),),
                )
            return {"ok": True}
    finally:
        con.close()


@app.post("/api/alerts/test")
def test_email():
    """Invia un messaggio di prova con la configurazione salvata."""
    con = db()
    try:
        with con.cursor() as cur:
            valori = get_settings_dict(cur)
            try:
                destinatari = mailer.send_mail(
                    valori,
                    "[iLO Monitor] Messaggio di prova",
                    "Se leggi questo messaggio, la configurazione SMTP di "
                    "iLO Monitor funziona.\n\n"
                    "Nessuna azione richiesta.",
                )
            except mailer.MailError as exc:
                cur.execute(
                    """
                    INSERT INTO alert_log
                    (sent_at, subject, recipients, status, error_message)
                    VALUES (NOW(),'Messaggio di prova',%s,'ERROR',%s)
                    """,
                    (valori.get("smtp_to", "")[:255], str(exc)),
                )
                return JSONResponse(
                    status_code=200,
                    content={"ok": False, "error": str(exc)},
                )

            cur.execute(
                """
                INSERT INTO alert_log
                (sent_at, subject, recipients, status)
                VALUES (NOW(),'Messaggio di prova',%s,'SENT')
                """,
                (", ".join(destinatari)[:255],),
            )
            return {
                "ok": True,
                "message": f"Inviato a {', '.join(destinatari)}",
            }
    finally:
        con.close()


@app.put("/api/alerts/rules/{server_id}")
def write_rule(server_id: int, payload: AlertRuleIn):
    valori = payload.model_dump(exclude_none=True)
    applica_a_tutti = bool(valori.pop("apply_to_all", False))

    severita = valori.pop("min_severity", None)
    if severita is not None and severita not in SEVERITA_AMMESSE:
        raise HTTPException(
            400, "Gravita' minima non valida: " + ", ".join(SEVERITA_AMMESSE)
        )

    sets, args = [], []
    for campo in CAMPI_REGOLA:
        if campo in valori:
            sets.append(f"{campo}=%s")
            args.append(1 if valori[campo] else 0)
    if severita is not None:
        sets.append("min_severity=%s")
        args.append(severita)

    if not sets:
        raise HTTPException(400, "Nessuna modifica da salvare")

    con = db()
    try:
        with con.cursor() as cur:
            if applica_a_tutti:
                # Solo qui serve coprire tutti i server.
                cur.execute(
                    "INSERT IGNORE INTO server_alerts (server_id) "
                    "SELECT id FROM servers"
                )
                cur.execute(f"UPDATE server_alerts SET {', '.join(sets)}", args)
                return {
                    "ok": True,
                    "message": "Impostazioni applicate a tutti i server",
                }

            cur.execute(
                "INSERT IGNORE INTO server_alerts (server_id) VALUES (%s)",
                (server_id,),
            )
            args.append(server_id)
            cur.execute(
                f"UPDATE server_alerts SET {', '.join(sets)} WHERE server_id=%s",
                args,
            )
            if not cur.rowcount:
                raise HTTPException(404, "Server non trovato")
            return {"ok": True}
    finally:
        con.close()


@app.post("/api/maintenance/purge-login-events")
def purge_login_events():
    """Rimuove dall'archivio gli eventi di accesso all'iLO gia' salvati.

    Restano comunque nel log dell'iLO: qui togliamo solo la copia che
    gonfia contatori e pagina eventi.
    """
    con = db()
    try:
        with con.cursor() as cur:
            cur.execute("SET SESSION max_statement_time=0")
            cur.execute(
                """
                DELETE FROM ilo_events
                WHERE message_id IN ('35.1017','35.1018','35.1015','35.1016')
                   OR message LIKE 'Browser login%%'
                   OR message LIKE 'Browser logout%%'
                   OR message LIKE 'XML login%%'
                   OR message LIKE 'XML logout%%'
                   OR message LIKE 'SSH login%%'
                   OR message LIKE 'SSH logout%%'
                """
            )
            return {
                "ok": True,
                "removed": cur.rowcount,
                "message": f"{cur.rowcount} eventi di accesso rimossi",
            }
    finally:
        con.close()


@app.post("/api/maintenance/purge")
def purge(background: BackgroundTasks):
    background.add_task(collector.purge_old_data)
    return {"ok": True, "message": "Pulizia dello storico avviata"}
