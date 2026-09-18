"""API HTTP di iLO Monitor.

Espone la dashboard (web/index.html) e tutti gli endpoint usati
dall'interfaccia: elenco e dettaglio server, aggiunta/modifica/rimozione,
raccolta su richiesta, eventi, mappe termiche, report e impostazioni.
"""

import os
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


def public_server(row):
    """Rimuove password e token di sessione prima di inviare al browser."""
    if not row:
        return row
    clean = dict(row)
    clean.pop("ilo_password_enc", None)
    clean.pop("ilo_session_token", None)
    clean.pop("ilo_session_location", None)
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


@app.get("/login")
def login_page():
    return FileResponse(f"{BASE_DIR}/web/login.html")


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
    return FileResponse(f"{BASE_DIR}/web/index.html")


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
                """
                SELECT
                    s.id,
                    s.overall_health,
                    s.last_collect_status,
                    -- Temperatura d'aspirazione: e' il dato che descrive
                    -- l'ambiente. Se iLO non riporta AmbTemp ripieghiamo
                    -- sul sensore di inlet del telaio.
                    COALESCE(
                        (SELECT sm.ambient_temperature
                           FROM system_metrics sm
                          WHERE sm.server_id=s.id
                            AND sm.ambient_temperature IS NOT NULL
                          ORDER BY sm.id DESC LIMIT 1),
                        (SELECT ts.temperature_c
                           FROM thermal_sensors ts
                          WHERE ts.server_id=s.id
                            AND ts.sensor_name LIKE '%%Inlet%%'
                            AND ts.temperature_c > 0
                          ORDER BY ts.id DESC LIMIT 1)
                    ) AS ambient_temp,
                    (SELECT MAX(ts.temperature_c)
                       FROM thermal_sensors ts
                      WHERE ts.server_id=s.id
                        AND ts.collected_at >= NOW() - INTERVAL 2 HOUR
                    ) AS max_temp,
                    (SELECT pm.consumed_watts
                       FROM power_metrics pm
                      WHERE pm.server_id=s.id
                      ORDER BY pm.id DESC LIMIT 1) AS watts
                FROM servers s
                WHERE s.enabled=1
                """,
            )

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
            total_power = sum(
                float(x["watts"]) for x in servers if x["watts"] is not None
            )

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
                    "avg_power": round(total_power / len(servers), 1)
                    if servers
                    else None,
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

SERVER_LIST_SQL = """
    SELECT
        s.*,
        (SELECT sm.collected_at FROM system_metrics sm
          WHERE sm.server_id=s.id ORDER BY sm.id DESC LIMIT 1
        ) AS metrics_at,
        (SELECT sm.cpu_utilization FROM system_metrics sm
          WHERE sm.server_id=s.id ORDER BY sm.id DESC LIMIT 1
        ) AS cpu_utilization,
        (SELECT sm.cpu_power_watts FROM system_metrics sm
          WHERE sm.server_id=s.id ORDER BY sm.id DESC LIMIT 1
        ) AS cpu_power_watts,
        (SELECT sm.ambient_temperature FROM system_metrics sm
          WHERE sm.server_id=s.id ORDER BY sm.id DESC LIMIT 1
        ) AS ambient_temperature,
        (SELECT sm.io_bus_utilization FROM system_metrics sm
          WHERE sm.server_id=s.id ORDER BY sm.id DESC LIMIT 1
        ) AS io_bus_utilization,
        (SELECT sm.memory_bus_utilization FROM system_metrics sm
          WHERE sm.server_id=s.id ORDER BY sm.id DESC LIMIT 1
        ) AS memory_bus_utilization,
        (SELECT pm.consumed_watts FROM power_metrics pm
          WHERE pm.server_id=s.id ORDER BY pm.id DESC LIMIT 1
        ) AS consumed_watts,
        (SELECT pm.average_watts FROM power_metrics pm
          WHERE pm.server_id=s.id ORDER BY pm.id DESC LIMIT 1
        ) AS average_watts,
        (SELECT MAX(ts.temperature_c) FROM thermal_sensors ts
          WHERE ts.server_id=s.id
            AND ts.collected_at >= NOW() - INTERVAL 2 HOUR
        ) AS max_temperature,
        (SELECT COUNT(*) FROM ilo_events e
          WHERE e.server_id=s.id
            AND e.event_created >= NOW() - INTERVAL 24 HOUR
        ) AS events_24h
    FROM servers s
    {where}
    ORDER BY s.name
"""


@app.get("/api/servers")
def servers(include_disabled: bool = Query(True)):
    where = "" if include_disabled else "WHERE s.enabled=1"
    con = db()
    try:
        with con.cursor() as cur:
            rows = many(cur, SERVER_LIST_SQL.format(where=where))
            return {"ok": True, "data": [public_server(r) for r in rows]}
    finally:
        con.close()


@app.get("/api/servers/{server_id}")
def server_detail(server_id: int):
    con = db()
    try:
        with con.cursor() as cur:
            s = one(
                cur,
                SERVER_LIST_SQL.format(where="WHERE s.id=%s"),
                (server_id,),
            )
            if not s:
                raise HTTPException(404, "Server non trovato")

            return {
                "ok": True,
                "data": {
                    "server": public_server(s),
                    "metric": one(
                        cur,
                        "SELECT * FROM system_metrics WHERE server_id=%s "
                        "ORDER BY id DESC LIMIT 1",
                        (server_id,),
                    ),
                    "power": one(
                        cur,
                        "SELECT * FROM power_metrics WHERE server_id=%s "
                        "ORDER BY id DESC LIMIT 1",
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
                    "drives": latest_by(
                        cur, "physical_drives", "drive_id", server_id
                    ),
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
                        "WHERE server_id=%s ORDER BY id DESC LIMIT 10",
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
        identity = collector.probe(
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
                 memory_total_gib, server_group, notes, enabled, last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s)
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
            if credentials_changed:
                try:
                    collector.probe(
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
            # Le tabelle figlie hanno ON DELETE CASCADE.
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
        identity = collector.probe(ip, user, password)
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


@app.post("/api/servers/{server_id}/led")
def toggle_led(server_id: int):
    """Accende o spegne il LED di identificazione (UID)."""
    con = db()
    try:
        with con.cursor() as cur:
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
