"""Collector Redfish multi-server per HPE iLO.

Differenze rispetto alla v1:
  - le credenziali non stanno piu' nel file .env ma nella tabella
    `servers`, cifrate con Fernet (vedi crypto_util.py);
  - un'unica esecuzione interroga tutti i server abilitati;
  - un errore su un server non blocca gli altri;
  - vengono raccolti anche processori, moduli di memoria, stato di
    alimentazione e data dell'ultimo avvio.

Uso da riga di comando:
    python3 -m app.redfish_collector              # tutti i server abilitati
    python3 -m app.redfish_collector --server 3   # solo il server con id 3
    python3 -m app.redfish_collector --list       # elenca i server configurati
"""

import argparse
import contextlib
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone

import httpx
import pymysql
from dotenv import load_dotenv

try:
    from app.crypto_util import decrypt, encrypt
    from app import alerts
except ImportError:  # esecuzione diretta dalla cartella app/
    from crypto_util import decrypt, encrypt
    import alerts

# Le connessioni agli iLO usano certificati autofirmati e vengono
# fatte con verify=False: httpx non emette avvisi per questo, quindi
# non serve silenziare nulla. (Il vecchio import di urllib3 era un
# residuo: httpx non lo usa, e in un contenitore snello non c'e'.)

BASE_DIR = os.getenv("ILO_MONITOR_BASE", "/opt/ilo-monitor")
load_dotenv(f"{BASE_DIR}/config/.env")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "ilomonitor")
DB_USER = os.getenv("DB_USER", "ilomonitor")
DB_PASSWORD = os.getenv("DB_PASSWORD")

HTTP_TIMEOUT = float(os.getenv("REDFISH_TIMEOUT", "30"))

# HPE usa un vocabolario proprio per la gravita' degli eventi.
# Lo riportiamo ai valori Redfish standard cosi' filtri e conteggi
# si comportano allo stesso modo su tutte le generazioni di iLO.
# Voci che l'iLO scrive ogni volta che qualcuno apre una sessione,
# monitoraggio compreso. Non si possono disattivare dall'iLO: l'unica
# impostazione disponibile riguarda le autenticazioni FALLITE. Le
# filtriamo qui, in ingresso, per non sommergere cruscotto e contatori.
LOGIN_MESSAGE_IDS = {"35.1017", "35.1018", "35.1015", "35.1016"}
LOGIN_PREFIXES = (
    "browser login",
    "browser logout",
    "xml login",
    "xml logout",
    "ssh login",
    "ssh logout",
    "redfish login",
    "redfish logout",
)


def is_login_event(message_id, message):
    """Vero se la voce e' un accesso o una disconnessione all'iLO."""
    if message_id and str(message_id).strip() in LOGIN_MESSAGE_IDS:
        return True
    testo = str(message or "").strip().lower()
    return testo.startswith(LOGIN_PREFIXES)


SEVERITY_MAP = {
    "informational": "Informational",
    "ok": "Informational",
    "repaired": "Informational",
    "caution": "Warning",
    "warning": "Warning",
    "critical": "Critical",
    "fatal": "Critical",
}


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def db_connect():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        autocommit=False,
    )


def oem(obj):
    """Estensione proprietaria HPE di una risorsa Redfish.

    iLO 5 e 6 usano la chiave "Hpe", iLO 4 usa "Hp". Senza questo
    controllo su iLO 4 si perdono temperatura d'aspirazione, consumi
    per componente, data dell'ultimo avvio e gravita' degli eventi.
    """
    if not isinstance(obj, dict):
        return {}
    block = obj.get("Oem", {})
    if not isinstance(block, dict):
        return {}
    for key in ("Hpe", "Hp"):
        value = block.get(key)
        if isinstance(value, dict):
            return value
    return {}


def members(collection):
    """Elementi di una collezione Redfish.

    Le versioni Redfish esposte da iLO 4 usano "Items" al posto di
    "Members"; alcune risorse mettono i collegamenti sotto "links".
    """
    if not isinstance(collection, dict):
        return []
    for key in ("Members", "Items"):
        value = collection.get(key)
        if isinstance(value, list):
            return value
    links = collection.get("links", {})
    if isinstance(links, dict):
        value = links.get("Member")
        if isinstance(value, list):
            return value
    return []


def all_members(rf, uri, max_pages=50):
    """Tutti gli elementi di una collezione, seguendo la paginazione.

    Gli iLO restituiscono i log a pagine: iLO 5 e 6 indicano la
    successiva con "Members@odata.nextLink", iLO 4 con
    links.NextPage.page da passare come parametro ?page=N. Senza
    seguirle si leggono solo le prime decine di voci.
    """
    collected = []
    seen_pages = set()
    current = uri
    page = 1

    for _ in range(max_pages):
        payload = rf.try_get(current)
        if not payload:
            break

        batch = members(payload)
        if not batch:
            break
        collected.extend(batch)

        # Forma standard Redfish.
        next_uri = payload.get("Members@odata.nextLink")
        if next_uri:
            if next_uri in seen_pages:
                break
            seen_pages.add(next_uri)
            current = next_uri
            continue

        # Forma usata dalle versioni piu' vecchie.
        next_page = payload.get("links", {})
        next_page = (
            next_page.get("NextPage", {}) if isinstance(next_page, dict) else {}
        )
        number = next_page.get("page") if isinstance(next_page, dict) else None
        if number and number != page:
            page = number
            base = uri.split("?")[0]
            current = f"{base}?page={number}"
            if current in seen_pages:
                break
            seen_pages.add(current)
            continue

        # Alcune collezioni dichiarano il totale senza indicare la
        # pagina successiva: proseguiamo finche' non lo raggiungiamo.
        total = payload.get("Total") or payload.get("Members@odata.count")
        if total and len(collected) < int(total):
            page += 1
            base = uri.split("?")[0]
            current = f"{base}?page={page}"
            if current in seen_pages:
                break
            seen_pages.add(current)
            continue

        break

    return collected


def life_left(value, consumed=False):
    """Vita residua di un disco, in percentuale 0-100.

    Redfish standard espone PredictedMediaLifeLeftPercent, cioe' la
    vita che RESTA. L'estensione HPE SmartStorage espone invece
    SSDEnduranceUtilizationPercentage, cioe' quella CONSUMATA: i due
    valori sono l'uno il complemento dell'altro e vanno convertiti,
    altrimenti un disco nuovo risulta a fine vita.

    Valori fuori scala non sono attendibili e vengono scartati:
    meglio nessun dato che una percentuale inventata.
    """
    v = f(value)
    if v is None:
        return None
    if consumed:
        v = 100 - v
    if v < 0 or v > 100:
        return None
    return v


def watt(value):
    """Watt misurati, None se l'iLO non misura.

    Sui server con alimentatore non gestito (per esempio ML30 Gen9 con
    alimentatore ATX) l'iLO non legge il consumo e risponde 0 invece di
    omettere il campo. Un server acceso non consuma zero watt, quindi
    zero significa "non misurato": salvarlo come numero falserebbe
    totali, medie e grafici.
    """
    v = f(value)
    if v is None or v <= 0:
        return None
    return v


def member_key(item, index, prefix="item"):
    """Identificativo stabile di un componente Redfish.

    iLO 5 popola MemberId oppure Id, iLO 4 spesso nessuno dei due.
    Le colonne corrispondenti non ammettono NULL, quindi ripieghiamo
    sull'ultimo segmento di @odata.id e infine sulla posizione nella
    collezione, che su una stessa macchina resta stabile.
    """
    if isinstance(item, dict):
        for field in ("MemberId", "Id"):
            value = item.get(field)
            if value is not None and str(value).strip() != "":
                return str(value).strip()

        bay = oem(item).get("BayNumber")
        if bay is not None:
            return str(bay)

        uri = item.get("@odata.id")
        if uri:
            segment = str(uri).rstrip("/").rsplit("/", 1)[-1]
            if segment:
                return segment

    return f"{prefix}{index}"


def f(value):
    """Converte in float, None se il valore non e' numerico."""
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def i(value):
    v = f(value)
    return int(v) if v is not None else None


def parse_redfish_time(value):
    """Converte un timestamp Redfish (ISO 8601) in DATETIME MySQL."""
    if not value or not isinstance(value, str):
        return None
    text = value.replace("T", " ").replace("Z", "")
    text = text.split("+")[0].split(".")[0].strip()
    try:
        datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return text


# ================================================================
# CLIENT REDFISH
# ================================================================


class Redfish:
    """Sessione Redfish verso un singolo iLO."""

    def __init__(self, ip, username, password, verify=False,
                 token=None, session_location=None):
        self.host = f"https://{ip}".rstrip("/")
        self.username = username
        self.password = password
        self.verify = verify
        # Una sessione gia' aperta puo' essere passata dal chiamante:
        # riutilizzarla evita di riempire il log eventi dell'iLO con
        # una coppia login/logout a ogni raccolta.
        self.token = token
        self.session_location = session_location
        self.reused = bool(token)
        # iLO 4 con firmware datato non espone SessionService: in quel
        # caso si ripiega sull'autenticazione HTTP Basic, che Redfish
        # ammette e che iLO accetta su tutte le generazioni.
        self.basic = False

    def _auth(self):
        return (self.username, self.password) if self.basic else None

    def create_session(self):
        if self.basic:
            return
        # Lo slash finale e' obbligatorio su iLO 4, che altrimenti
        # risponde 308 verso lo stesso indirizzo con lo slash.
        url = self.host + "/redfish/v1/SessionService/Sessions/"
        try:
            response = httpx.post(
                url,
                json={"UserName": self.username, "Password": self.password},
                verify=self.verify,
                timeout=HTTP_TIMEOUT,
                follow_redirects=True,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
        except Exception as exc:
            raise RuntimeError(f"iLO non raggiungibile: {exc}") from exc

        if response.status_code == 401:
            raise RuntimeError("Credenziali iLO rifiutate (HTTP 401)")

        if response.status_code != 201:
            # Niente SessionService utilizzabile: proviamo in Basic e
            # verifichiamo subito che le credenziali siano valide.
            self.basic = True
            probe = httpx.get(
                self.host + "/redfish/v1/Systems/1/",
                verify=self.verify,
                timeout=HTTP_TIMEOUT,
                follow_redirects=True,
                auth=(self.username, self.password),
                headers={"Accept": "application/json", "Connection": "close"},
            )
            if probe.status_code == 401:
                raise RuntimeError("Credenziali iLO rifiutate (HTTP 401)")
            if probe.status_code != 200:
                self.basic = False
                raise RuntimeError(
                    f"Creazione sessione Redfish fallita: HTTP "
                    f"{response.status_code}: {response.text[:300]}"
                )
            print("    sessione non disponibile, uso autenticazione Basic")
            return

        self.token = response.headers.get("X-Auth-Token")
        self.session_location = response.headers.get("Location")
        self.reused = False
        if not self.token:
            raise RuntimeError("Sessione creata ma X-Auth-Token assente")

    def _url(self, path):
        clean = path if path.startswith("/") else "/" + path
        if clean.startswith("/redfish/v1"):
            return self.host + clean
        return self.host + "/redfish/v1" + clean

    def _headers(self, extra=None):
        headers = {"Accept": "application/json", "Connection": "close"}
        if self.token:
            headers["X-Auth-Token"] = self.token
        if extra:
            headers.update(extra)
        return headers

    def get(self, path):
        if not self.token and not self.basic:
            self.create_session()

        url = self._url(path)
        response = httpx.get(
            url,
            verify=self.verify,
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            auth=self._auth(),
            headers=self._headers(),
        )

        if response.status_code == 401 and not self.basic:
            # Sessione scaduta: ne apriamo una nuova e riproviamo una volta.
            self.discard()
            self.create_session()
            response = httpx.get(
                url,
                verify=self.verify,
                timeout=HTTP_TIMEOUT,
                follow_redirects=True,
                auth=self._auth(),
                headers=self._headers(),
            )

        if response.status_code != 200:
            raise RuntimeError(
                f"GET Redfish fallita: {path} -> HTTP "
                f"{response.status_code}: {response.text[:300]}"
            )
        return response.json()

    def try_get(self, path, retries=0, quiet=False):
        """Come get() ma restituisce None se l'endpoint non esiste.

        Con retries>0 riprova sugli errori temporanei: l'iLO risponde
        ResourceNotReadyRetry quando il controller di storage sta
        ancora inizializzando, e in quel caso la risorsa esiste
        eccome, va solo richiesta di nuovo.
        """
        for tentativo in range(retries + 1):
            try:
                return self.get(path)
            except Exception as exc:
                messaggio = str(exc)
                temporaneo = (
                    "ResourceNotReadyRetry" in messaggio
                    or "HTTP 503" in messaggio
                )
                if temporaneo and tentativo < retries:
                    attesa = 3 * (tentativo + 1)
                    print(
                        f"    {path} non ancora pronto, riprovo fra {attesa}s"
                    )
                    time.sleep(attesa)
                    continue
                if not quiet:
                    print(f"    endpoint {path} non disponibile: {exc}")
                return None
        return None

    def post(self, path, payload):
        if not self.token and not self.basic:
            self.create_session()
        response = httpx.post(
            self._url(path),
            json=payload,
            verify=self.verify,
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            auth=self._auth(),
            headers=self._headers({"Content-Type": "application/json"}),
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"POST Redfish fallita: {path} -> HTTP "
                f"{response.status_code}: {response.text[:300]}"
            )
        return response

    def patch(self, path, payload):
        if not self.token and not self.basic:
            self.create_session()
        response = httpx.patch(
            self._url(path),
            json=payload,
            verify=self.verify,
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            auth=self._auth(),
            headers=self._headers({"Content-Type": "application/json"}),
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"PATCH Redfish fallita: {path} -> HTTP "
                f"{response.status_code}: {response.text[:300]}"
            )
        return response

    def discard(self):
        """Dimentica la sessione senza contattare l'iLO."""
        self.token = None
        self.session_location = None
        self.reused = False

    def close(self):
        if self.basic:
            return
        if not self.token or not self.session_location:
            self.token = None
            self.session_location = None
            return
        location = self.session_location
        url = (
            location
            if location.startswith(("http://", "https://"))
            else self.host + location
        )
        try:
            httpx.delete(
                url,
                verify=self.verify,
                timeout=15.0,
                headers={"X-Auth-Token": self.token, "Connection": "close"},
            )
        except Exception as exc:
            print(f"    logout sessione Redfish non riuscito: {exc}")
        self.token = None
        self.session_location = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def probe(ip, username, password):
    """Verifica le credenziali e restituisce l'identita' del server.

    Usata dalla UI sia per il pulsante "Prova connessione" sia per
    precompilare modello e seriale quando si aggiunge un server.
    """
    with Redfish(ip, username, password) as rf:
        system = rf.get("/Systems/1/")
        manager = rf.get("/Managers/1/")
        status = system.get("Status", {})
        cpu_summary = system.get("ProcessorSummary", {})
        mem_summary = system.get("MemorySummary", {})
        return {
            "hostname": system.get("HostName"),
            "manufacturer": system.get("Manufacturer"),
            "model": system.get("Model"),
            "serial_number": system.get("SerialNumber"),
            "uuid": system.get("UUID"),
            "bios_version": system.get("BiosVersion"),
            "ilo_version": manager.get("Model"),
            "ilo_firmware": manager.get("FirmwareVersion"),
            "ilo_license": (oem(manager).get("License", {}) or {}).get(
                "LicenseString"
            ),
            "overall_health": status.get("Health"),
            "state": status.get("State"),
            "power_state": system.get("PowerState"),
            "processor_model": cpu_summary.get("Model"),
            "processor_count": cpu_summary.get("Count"),
            "memory_total_gib": mem_summary.get("TotalSystemMemoryGiB"),
        }


def identifica(ip, username, password):
    """Come probe(), ma riconosce anche gli iLO 2 e 3.

    Restituisce (identita', protocollo): "redfish" oppure "ribcl".
    Redfish si prova per primo; se fallisce si guarda se all'indirizzo
    c'e' un iLO di vecchia generazione, e in quel caso si usa RIBCL.
    Altrimenti resta l'errore di Redfish, che e' quello significativo.
    """
    try:
        return probe(ip, username, password), "redfish"
    except Exception as errore_redfish:
        try:
            from app import ribcl
        except ImportError:
            import ribcl
        if not ribcl.e_ilo_ribcl(ip):
            raise errore_redfish
        rib = ribcl.Ribcl(ip, username, password)
        return ribcl.identita(rib), "ribcl"


# ================================================================
# RACCOLTA DATI DI UN SINGOLO SERVER
# ================================================================


def collect_server(server, db, verbose=True, full=False):
    """Raccoglie tutti i dati di un server. `server` e' una riga dict
    della tabella servers. Restituisce un riepilogo dell'operazione."""

    # Gli iLO 2 e 3 non hanno Redfish: li legge il modulo RIBCL, che
    # scrive nelle stesse tabelle.
    if str(server.get("ilo_protocol") or "").lower() == "ribcl":
        try:
            from app import ribcl_collector
        except ImportError:
            import ribcl_collector
        return ribcl_collector.collect_server(
            server, db, verbose=verbose, full=full)

    server_id = server["id"]
    name = server["name"]
    ip = server["ilo_ip"]

    def log(msg):
        if verbose:
            print(msg)

    log("")
    log("-" * 66)
    log(f"{name}  ({ip})")
    log("-" * 66)

    password = decrypt(server.get("ilo_password_enc"))
    if not password:
        raise RuntimeError(
            "Password iLO non configurata: modificare il server "
            "dall'interfaccia e reinserirla."
        )

    cur = db.cursor()
    started = now()

    # Inventario e log si rileggono a intervalli piu' larghi delle
    # metriche: sono la parte cara e cambiano di rado.
    intervallo = int(read_setting(cur, "inventory_interval_minutes", 60) or 60)
    ultimo_inventario = server.get("last_inventory_at")
    fare_inventario = (
        full
        or not ultimo_inventario
        or (now() - ultimo_inventario).total_seconds() >= intervallo * 60
    )

    # Riprendiamo la sessione della raccolta precedente se e' ancora
    # plausibilmente valida. L'iLO chiude le sessioni inattive dopo
    # 30 minuti, quindi oltre i 25 ne apriamo una nuova senza
    # sprecare una richiesta destinata a fallire.
    stored_token = None
    stored_location = server.get("ilo_session_location")
    session_at = server.get("ilo_session_at")
    if server.get("ilo_session_token") and session_at:
        age = (now() - session_at).total_seconds()
        if age < 25 * 60:
            try:
                stored_token = decrypt(server["ilo_session_token"])
            except Exception:
                stored_token = None
    if not stored_token:
        stored_location = None

    rf = Redfish(
        ip,
        server.get("ilo_user") or "Administrator",
        password,
        token=stored_token,
        session_location=stored_location,
    )

    cur.execute(
        """
        INSERT INTO collection_runs (server_id, started_at, status)
        VALUES (%s, %s, 'RUNNING')
        """,
        (server_id, started),
    )
    run_id = cur.lastrowid
    db.commit()

    try:
        collected = now()

        # ---------- IDENTITA' ----------
        log("  [1/9] sistema e manager")
        root = rf.get("/")
        system = rf.get("/Systems/1/")
        manager = rf.get("/Managers/1/")

        status = system.get("Status", {})
        cpu_summary = system.get("ProcessorSummary", {})
        mem_summary = system.get("MemorySummary", {})
        hpe_system = oem(system)

        # Il telaio non si chiama "1" su tutte le generazioni: lo
        # ricaviamo dai collegamenti del sistema, con "1" come ripiego.
        chassis_id = "1"
        chassis_links = system.get("Links", {}).get("Chassis", [])
        if chassis_links:
            uri = chassis_links[0].get("@odata.id", "")
            segment = str(uri).rstrip("/").rsplit("/", 1)[-1]
            if segment:
                chassis_id = segment

        cur.execute(
            """
            UPDATE servers SET
                hostname=%s,
                ilo_version=%s,
                ilo_firmware=%s,
                manufacturer=%s,
                model=%s,
                serial_number=%s,
                uuid=%s,
                bios_version=%s,
                overall_health=%s,
                state=%s,
                power_state=%s,
                indicator_led=%s,
                ilo_license=%s,
                last_boot_at=%s,
                processor_summary=%s,
                processor_count=%s,
                memory_total_gib=%s,
                ams_status=%s,
                host_os=%s,
                last_seen=%s
            WHERE id=%s
            """,
            (
                system.get("HostName"),
                manager.get("Model"),
                manager.get("FirmwareVersion"),
                system.get("Manufacturer"),
                system.get("Model"),
                system.get("SerialNumber"),
                system.get("UUID"),
                system.get("BiosVersion"),
                status.get("Health"),
                status.get("State"),
                system.get("PowerState"),
                system.get("IndicatorLED"),
                (oem(manager).get("License", {}) or {}).get("LicenseString"),
                parse_redfish_time(
                    hpe_system.get("PostDiscoveryCompleteTimeStamp")
                ),
                cpu_summary.get("Model"),
                i(cpu_summary.get("Count")),
                f(mem_summary.get("TotalSystemMemoryGiB")),
                # Agentless Management Service: gira nel sistema operativo
                # e passa all'iLO indirizzi IP, stato delle schede di rete
                # e dischi sul SATA integrato. Senza, l'iLO non li vede.
                (hpe_system.get("AggregateHealthStatus") or {})
                .get("AgentlessManagementService"),
                ((hpe_system.get("HostOS") or {}).get("OsName") or "").strip()
                or None,
                collected,
                server_id,
            ),
        )

        # ---------- ALIMENTAZIONE ----------
        log("  [2/9] alimentazione")
        power = rf.try_get(f"/Chassis/{chassis_id}/Power/") or {}

        pc = {}
        for item in power.get("PowerControl", []):
            if isinstance(item, dict):
                pc = item
                break

        # Redfish mette media, minimo e massimo in PowerMetrics, non
        # direttamente in PowerControl. Alcuni firmware datati li
        # riportano al primo livello: in quel caso ripieghiamo li'.
        metriche = pc.get("PowerMetrics")
        if not isinstance(metriche, dict) or not metriche:
            metriche = pc

        def find_power_metric(obj):
            if isinstance(obj, dict):
                if "PowerMetric" in obj:
                    return obj["PowerMetric"]
                for v in obj.values():
                    found = find_power_metric(v)
                    if found is not None:
                        return found
            elif isinstance(obj, list):
                for v in obj:
                    found = find_power_metric(v)
                    if found is not None:
                        return found
            return None

        pm = find_power_metric(oem(power)) or {}

        cur.execute(
            """
            INSERT INTO power_metrics
            (server_id, collected_at, consumed_watts, average_watts,
             maximum_watts, minimum_watts, cpu_watts, dimm_watts,
             gpu_watts, power_capacity_watts)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                server_id,
                collected,
                watt(pc.get("PowerConsumedWatts")),
                watt(metriche.get("AverageConsumedWatts")),
                watt(metriche.get("MaxConsumedWatts")),
                watt(metriche.get("MinConsumedWatts")),
                f(pm.get("CpuWatts")),
                f(pm.get("DimmWatts")),
                f(pm.get("GpuWatts")),
                f(pc.get("PowerCapacityWatts")),
            ),
        )

        for index, psu in enumerate(power.get("PowerSupplies", []), start=1):
            st = psu.get("Status", {})
            cur.execute(
                """
                INSERT INTO power_supplies
                (server_id, collected_at, psu_id, name, capacity_watts,
                 power_input_watts, power_output_watts, health, state)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    member_key(psu, index, "psu"),
                    psu.get("Name"),
                    f(psu.get("PowerCapacityWatts")),
                    f(psu.get("PowerInputWatts")),
                    f(
                        psu.get("LastPowerOutputWatts")
                        if psu.get("LastPowerOutputWatts") is not None
                        else psu.get("PowerOutputWatts")
                    ),
                    st.get("Health"),
                    st.get("State"),
                ),
            )

        # ---------- METRICHE DI SISTEMA ----------
        system_usage = system.get("SystemUsage")
        if not isinstance(system_usage, dict):
            system_usage = hpe_system.get("SystemUsage", {})
        if not isinstance(system_usage, dict):
            system_usage = {}

        cur.execute(
            """
            INSERT INTO system_metrics
            (server_id, collected_at, cpu_utilization, cpu_power_watts,
             memory_utilization, memory_power_watts, io_bus_utilization,
             memory_bus_utilization, ambient_temperature)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                server_id,
                collected,
                f(system_usage.get("CPUUtil")),
                f(system_usage.get("CPU0Power")),
                None,
                None,
                f(system_usage.get("IOBusUtil")),
                f(system_usage.get("MemoryBusUtil")),
                f(pm.get("AmbTemp")),
            ),
        )

        # ---------- TERMICA E VENTOLE ----------
        log("  [3/9] temperature e ventole")
        thermal = rf.try_get(f"/Chassis/{chassis_id}/Thermal/") or {}

        for index, sensor in enumerate(thermal.get("Temperatures", []), start=1):
            st = sensor.get("Status", {})
            cur.execute(
                """
                INSERT INTO thermal_sensors
                (server_id, collected_at, sensor_name, sensor_number,
                 temperature_c, health, state, warning_threshold,
                 critical_threshold, fatal_threshold)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    sensor.get("Name") or member_key(sensor, index, "sensore"),
                    sensor.get("MemberId"),
                    f(sensor.get("ReadingCelsius")),
                    st.get("Health"),
                    st.get("State"),
                    f(sensor.get("UpperThresholdNonCritical")),
                    f(sensor.get("UpperThresholdCritical")),
                    f(sensor.get("UpperThresholdFatal")),
                ),
            )

        for index, fan in enumerate(thermal.get("Fans", []), start=1):
            st = fan.get("Status", {})
            speed = fan.get("FanSpeedPercent")
            if isinstance(speed, dict):
                speed = speed.get("SpeedPercent")
            if speed is None:
                speed = fan.get("Reading")
            # iLO 4 usa CurrentReading, con l'unita' in "Units" (di
            # solito Percent). Se l'unita' sono giri al minuto il
            # numero non e' una percentuale e non va mostrato come tale.
            if speed is None and fan.get("CurrentReading") is not None:
                unita = str(fan.get("Units") or "Percent").lower()
                if unita in ("percent", "%"):
                    speed = fan.get("CurrentReading")
            cur.execute(
                """
                INSERT INTO fans
                (server_id, collected_at, fan_id, fan_name, status,
                 health, state, speed_percent)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    member_key(fan, index, "fan"),
                    fan.get("Name"),
                    fan.get("StatusIndicator"),
                    st.get("Health"),
                    st.get("State"),
                    f(speed),
                ),
            )

        # ---------- INVENTARIO (a cadenza ridotta) ----------
        # CPU, memoria, dischi, rete e log costano la gran parte
        # delle richieste ma cambiano di rado: rileggerli a ogni
        # ciclo faceva durare la raccolta piu' dell'intervallo del
        # timer, che quindi ne avviava subito un'altra.
        if fare_inventario:
            # ---------- PROCESSORI ----------
            log("  [4/9] processori")
            processors = rf.try_get("/Systems/1/Processors/")
            core_total = 0
            if processors:
                for p_index, member in enumerate(
                        members(processors), start=1):
                    uri = member.get("@odata.id")
                    if not uri:
                        continue
                    cpu = rf.try_get(uri)
                    if not cpu:
                        continue
                    st = cpu.get("Status", {})
                    if str(st.get("State", "")).lower() == "absent":
                        continue
                    core_total += i(cpu.get("TotalCores")) or 0
                    cur.execute(
                        """
                        INSERT INTO processors
                        (server_id, collected_at, processor_id, socket, model,
                         manufacturer, max_speed_mhz, total_cores,
                         total_threads, health, state)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            server_id,
                            collected,
                            member_key(cpu, p_index, "cpu"),
                            cpu.get("Socket"),
                            cpu.get("Model"),
                            cpu.get("Manufacturer"),
                            i(cpu.get("MaxSpeedMHz")),
                            i(cpu.get("TotalCores")),
                            i(cpu.get("TotalThreads")),
                            st.get("Health"),
                            st.get("State"),
                        ),
                    )
                cur.execute(
                    "UPDATE servers SET core_count=%s WHERE id=%s",
                    (core_total or None, server_id),
                )

            # ---------- MEMORIA ----------
            log("  [5/9] moduli di memoria")
            memory = rf.try_get("/Systems/1/Memory/")
            if memory:
                for m_index, member in enumerate(
                        members(memory), start=1):
                    uri = member.get("@odata.id")
                    if not uri:
                        continue
                    dimm = rf.try_get(uri)
                    if not dimm:
                        continue
                    st = dimm.get("Status", {})
                    allowed = dimm.get("AllowedSpeedsMHz") or []
                    speed = dimm.get("OperatingSpeedMhz")
                    if speed is None and allowed:
                        speed = allowed[0]
                    cur.execute(
                        """
                        INSERT INTO memory_modules
                        (server_id, collected_at, dimm_id, device_locator,
                         capacity_mib, speed_mhz, memory_type, manufacturer,
                         part_number, rank_count, health, state)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            server_id,
                            collected,
                            member_key(dimm, m_index, "dimm"),
                            dimm.get("DeviceLocator"),
                            i(dimm.get("CapacityMiB")),
                            i(speed),
                            dimm.get("MemoryDeviceType") or dimm.get("MemoryType"),
                            dimm.get("Manufacturer"),
                            (dimm.get("PartNumber") or "").strip() or None,
                            i(dimm.get("RankCount")),
                            st.get("Health"),
                            st.get("State"),
                        ),
                    )

            # ---------- STORAGE ----------
            log("  [6/9] storage")
            # Gli iLO 4 non hanno l'elenco standard: lo storage sta solo in
            # SmartStorage, letto subito dopo. Un 404 qui e' normale.
            storage_collection = rf.try_get(
                "/Systems/1/Storage/", retries=2, quiet=True) or {}
            storage_found = 0
            # Cio' che il percorso standard ha gia' registrato, per non
            # duplicarlo quando poi si legge anche SmartStorage.
            visti = {"ctrl": set(), "disco": set(), "vol": set(), "vol_dim": [],
                     "senza_vita": {}}

            for member in members(storage_collection):
                storage_found += 1
                uri = member.get("@odata.id")
                if not uri:
                    continue
                # Su alcuni iLO 5 questi rispondono a lungo
                # ResourceNotReadyRetry: gli stessi dati arrivano da
                # SmartStorage, quindi non serve insistere ne' segnalarlo.
                storage = rf.try_get(uri, quiet=True)
                if not storage:
                    continue

                controller_uri = storage.get("Controllers", {}).get("@odata.id")
                if controller_uri:
                    controllers = rf.try_get(controller_uri) or {}
                    for c_index, ref in enumerate(
                            members(controllers), start=1):
                        controller = rf.try_get(ref.get("@odata.id", ""))
                        if not controller:
                            continue
                        st = controller.get("Status", {})
                        cache = controller.get("CacheSummary", {})
                        visti["ctrl"].add(chiave_controller(controller))
                        cur.execute(
                            """
                            INSERT INTO storage_controllers
                            (server_id, collected_at, controller_id,
                             manufacturer, model, firmware, cache_mib,
                             health, state)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """,
                            (
                                server_id,
                                collected,
                                "rf-" + str(storage.get("Id") or "") + "-"
                                + member_key(controller, c_index, "ctrl"),
                                controller.get("Manufacturer"),
                                controller.get("Model"),
                                controller.get("FirmwareVersion"),
                                f(cache.get("TotalCacheSizeMiB")),
                                st.get("Health"),
                                st.get("State"),
                            ),
                        )

                for d_index, drive_ref in enumerate(
                        storage.get("Drives", []), start=1):
                    drive_uri = drive_ref.get("@odata.id")
                    if not drive_uri:
                        continue
                    drive = rf.try_get(drive_uri)
                    if not drive:
                        continue
                    st = drive.get("Status", {})
                    location = drive.get("PhysicalLocation", {}).get(
                        "PartLocation", {}
                    )
                    seriale = (drive.get("SerialNumber") or "").strip() or None
                    vita = life_left(drive.get("PredictedMediaLifeLeftPercent"))
                    drive_id = ("rf-" + str(storage.get("Id") or "") + "-"
                                + member_key(drive, d_index, "disco"))
                    if seriale:
                        visti["disco"].add(seriale.upper())
                        # Alcuni SSD riportano qui valori impossibili (338%):
                        # SmartStorage puo' avere il dato giusto per lo
                        # stesso disco, e lo si recupera da li'.
                        if vita is None:
                            visti["senza_vita"][seriale.upper()] = drive_id
                    cur.execute(
                        """
                        INSERT INTO physical_drives
                        (server_id, collected_at, drive_id, bay, manufacturer,
                         model, revision, protocol, media_type, capacity_bytes,
                         rotation_rpm, negotiated_speed_gbs, health, state,
                         failure_predicted, media_life_left_percent,
                         serial_number)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            server_id,
                            collected,
                            # Prefisso per sorgente: le due fonti numerano i
                            # dischi ciascuna da capo, e "0" di una non e'
                            # "0" dell'altra.
                            drive_id,
                            location.get("ServiceLabel"),
                            drive.get("Manufacturer"),
                            drive.get("Model"),
                            drive.get("Revision"),
                            drive.get("Protocol"),
                            drive.get("MediaType"),
                            drive.get("CapacityBytes"),
                            f(drive.get("RotationSpeedRPM")),
                            f(drive.get("NegotiatedSpeedGbs")),
                            st.get("Health"),
                            st.get("State"),
                            drive.get("FailurePredicted"),
                            vita,
                            seriale,
                        ),
                    )

                volumes_uri = storage.get("Volumes", {}).get("@odata.id")
                if volumes_uri:
                    volumes = rf.try_get(volumes_uri) or {}
                    for v_index, ref in enumerate(
                            members(volumes), start=1):
                        volume = rf.try_get(ref.get("@odata.id", ""))
                        if not volume:
                            continue
                        st = volume.get("Status", {})
                        for ident in volume.get("Identifiers") or []:
                            if isinstance(ident, dict) and ident.get("DurableName"):
                                visti["vol"].add(str(ident["DurableName"]).upper())
                        visti["vol_dim"].append(
                            (raid_norm(volume.get("RAIDType")),
                             f(volume.get("CapacityBytes")))
                        )
                        cur.execute(
                            """
                            INSERT INTO storage_volumes
                            (server_id, collected_at, volume_id, name,
                             raid_type, capacity_bytes, health, state)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            """,
                            (
                                server_id,
                                collected,
                                "rf-" + str(storage.get("Id") or "") + "-"
                                + member_key(volume, v_index, "volume"),
                                volume.get("Name"),
                                volume.get("RAIDType"),
                                volume.get("CapacityBytes"),
                                st.get("Health"),
                                st.get("State"),
                            ),
                        )

            # SmartStorage si legge sempre, non solo come ripiego. I Gen9
            # con iLO 4 non espongono /Systems/1/Storage/ affatto; sui
            # Gen10 il RAID software S100i compare solo li', mentre
            # l'elenco standard mostra il controller SATA e basta. Cio'
            # che le due fonti hanno in comune (uno Smart Array vero
            # come il P408i) viene riconosciuto e non duplicato.
            collect_smart_storage(rf, cur, server_id, collected, log, visti)

            # ---------- RETE ----------
            log("  [7/9] interfacce di rete")
            network = rf.try_get("/Systems/1/EthernetInterfaces/") or {}
            for n_index, member in enumerate(members(network), start=1):
                interface = rf.try_get(member.get("@odata.id", ""))
                if not interface:
                    continue
                st = interface.get("Status", {})
                addresses = interface.get("IPv4Addresses", [])
                ipv4 = addresses[0].get("Address") if addresses else None
                cur.execute(
                    """
                    INSERT INTO network_interfaces
                    (server_id, collected_at, interface_id, name, mac_address,
                     ipv4_address, link_status, interface_enabled, speed_mbps,
                     health, state)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        server_id,
                        collected,
                        member_key(interface, n_index, "nic"),
                        interface.get("Name"),
                        interface.get("MACAddress"),
                        ipv4,
                        interface.get("LinkStatus"),
                        interface.get("InterfaceEnabled"),
                        f(interface.get("SpeedMbps")),
                        st.get("Health"),
                        st.get("State"),
                    ),
                )

            # ---------- EVENTI ----------
            log("  [8/9] log eventi")
            event_count = collect_logs(rf, cur, server_id, log)

            cur.execute(
                "UPDATE servers SET last_inventory_at=%s WHERE id=%s",
                (collected, server_id),
            )
        else:
            log(
                f"  [4-8/9] inventario e log saltati "
                f"(riletti ogni {intervallo} min)"
            )
            event_count = None

        # ---------- SNAPSHOT ----------
        log("  [9/9] snapshot Redfish")
        for endpoint, payload in {
            "/redfish/v1/": root,
            "/redfish/v1/Systems/1/": system,
            "/redfish/v1/Managers/1/": manager,
        }.items():
            cur.execute(
                """
                INSERT INTO raw_snapshots
                (server_id, collected_at, endpoint, payload)
                VALUES (%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    endpoint,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )

        cur.execute(
            """
            UPDATE collection_runs
            SET finished_at=%s, status='OK', error_message=NULL
            WHERE id=%s
            """,
            (now(), run_id),
        )
        cur.execute(
            """
            UPDATE servers
            SET last_collect_status='OK',
                last_collect_at=%s,
                last_error=NULL
            WHERE id=%s
            """,
            (now(), server_id),
        )
        db.commit()

        dettaglio_eventi = (
            f"{event_count} eventi" if event_count is not None
            else "solo metriche"
        )
        log(
            f"  OK - {system.get('Model')} / salute "
            f"{status.get('Health')} / {dettaglio_eventi} / "
            f"sessione {'riusata' if rf.reused else 'nuova'}"
        )
        return {
            "server_id": server_id,
            "name": name,
            "status": "OK",
            "model": system.get("Model"),
            "health": status.get("Health"),
            "events": event_count,
            "inventory": fare_inventario,
        }

    except Exception as exc:
        db.rollback()
        message = str(exc)[:1000]
        try:
            cur.execute(
                """
                UPDATE collection_runs
                SET finished_at=%s, status='ERROR', error_message=%s
                WHERE id=%s
                """,
                (now(), message, run_id),
            )
            cur.execute(
                """
                UPDATE servers
                SET last_collect_status='ERROR',
                    last_collect_at=%s,
                    last_error=%s
                WHERE id=%s
                """,
                (now(), message, server_id),
            )
            db.commit()
        except Exception:
            db.rollback()
        log(f"  ERRORE: {message}")
        return {
            "server_id": server_id,
            "name": name,
            "status": "ERROR",
            "error": message,
        }

    finally:
        # Gli avvisi si valutano a raccolta conclusa, sia riuscita sia
        # fallita: un server che non risponde e' esso stesso un avviso.
        try:
            with db.cursor(pymysql.cursors.DictCursor) as ac:
                ac.execute("SELECT * FROM servers WHERE id=%s", (server_id,))
                aggiornato = ac.fetchone()
            if aggiornato:
                alerts.valuta_e_invia(db, aggiornato, verbose=verbose)
        except Exception as exc:
            print(f"    avvisi non valutati: {exc}")

        # La sessione resta aperta e viene riusata alla prossima
        # raccolta: chiuderla qui costringerebbe l'iLO a registrare
        # un logout e un nuovo login ogni volta.
        try:
            with db.cursor() as sc:
                if rf.token and not rf.basic:
                    sc.execute(
                        """
                        UPDATE servers
                        SET ilo_session_token=%s,
                            ilo_session_location=%s,
                            ilo_session_at=%s
                        WHERE id=%s
                        """,
                        (
                            encrypt(rf.token),
                            rf.session_location,
                            now(),
                            server_id,
                        ),
                    )
                else:
                    sc.execute(
                        """
                        UPDATE servers
                        SET ilo_session_token=NULL,
                            ilo_session_location=NULL,
                            ilo_session_at=NULL
                        WHERE id=%s
                        """,
                        (server_id,),
                    )
            db.commit()
        except Exception as exc:
            db.rollback()
            print(f"    sessione non memorizzata: {exc}")
        cur.close()


# ================================================================
# ORCHESTRAZIONE
# ================================================================


def chiave_controller(controller):
    """Seriale del controller, o il modello se il seriale manca."""
    seriale = str(controller.get("SerialNumber") or "").strip().upper()
    if seriale:
        return "sn:" + seriale
    return "mod:" + str(controller.get("Model") or "").strip().upper()


def raid_norm(valore):
    """'RAID1', 'Raid1', '1' -> '1': le due fonti scrivono diversamente."""
    testo = str(valore or "").upper().replace("RAID", "").strip()
    return testo or None


def volume_gia_visto(visti, uid, raid, capacita):
    if uid and uid.upper() in visti["vol"]:
        return True
    # Senza identificativo confrontiamo livello RAID e capacita':
    # le due fonti arrotondano in modo diverso, quindi un 2% di
    # tolleranza.
    if capacita:
        for r, c in visti["vol_dim"]:
            if c and r == raid and abs(c - capacita) / max(c, capacita) < 0.02:
                return True
    return False


def collect_smart_storage(rf, cur, server_id, collected, log, visti=None):
    """Storage dei server Gen9 (iLO 4) via estensione SmartStorage.

    Le capacita' sono espresse in MiB anziche' in byte e i campi
    hanno nomi propri, quindi vanno convertiti prima di riusare le
    stesse tabelle del percorso Redfish standard.
    """
    if visti is None:
        visti = {"ctrl": set(), "disco": set(), "vol": set(), "vol_dim": []}

    # Su un server senza SmartStorage l'endpoint non esiste: va bene,
    # e non serve riempire il log con un 404 a ogni raccolta.
    root = rf.try_get("/Systems/1/SmartStorage/ArrayControllers/", quiet=True) or {}

    def mib_to_bytes(value):
        v = f(value)
        return int(v * 1024 * 1024) if v else None

    aggiunti = {"ctrl": 0, "disco": 0, "vol": 0}

    def leggi_dischi(percorso, prefisso):
        drives = rf.try_get(percorso, quiet=True) or {}
        trovati = 0
        for d_index, d_ref in enumerate(members(drives), start=1):
            drive = rf.try_get(d_ref.get("@odata.id", ""))
            if not drive:
                continue
            dst = drive.get("Status", {})
            seriale = (drive.get("SerialNumber") or "").strip() or None
            # Stesso disco gia' letto dal percorso standard: si salta.
            # Senza seriale non si puo' sapere, e si preferisce un
            # possibile doppione a un disco reale che sparisce.
            if seriale and seriale.upper() in visti["disco"]:
                da_completare = visti.get("senza_vita", {}).pop(seriale.upper(), None)
                vita_ss = life_left(
                    drive.get("SSDEnduranceUtilizationPercentage"), consumed=True)
                if da_completare and vita_ss is not None:
                    cur.execute(
                        "UPDATE physical_drives SET media_life_left_percent=%s "
                        "WHERE server_id=%s AND collected_at=%s AND drive_id=%s",
                        (vita_ss, server_id, collected, da_completare),
                    )
                    aggiunti["vita"] = aggiunti.get("vita", 0) + 1
                continue
            if seriale:
                visti["disco"].add(seriale.upper())
            aggiunti["disco"] += 1
            trovati += 1
            cur.execute(
                """
                INSERT INTO physical_drives
                (server_id, collected_at, drive_id, bay, manufacturer,
                 model, revision, protocol, media_type, capacity_bytes,
                 rotation_rpm, negotiated_speed_gbs, health, state,
                 failure_predicted, media_life_left_percent, serial_number,
                 endurance_used_percent, power_on_hours)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    prefisso + member_key(drive, d_index, "disco"),
                    drive.get("Location"),
                    None,
                    drive.get("Model"),
                    drive.get("FirmwareVersion", {}).get("Current", {})
                    .get("VersionString")
                    if isinstance(drive.get("FirmwareVersion"), dict)
                    else None,
                    drive.get("InterfaceType"),
                    drive.get("MediaType"),
                    mib_to_bytes(drive.get("CapacityMiB")),
                    f(drive.get("RotationalSpeedRpm")),
                    f(drive.get("InterfaceSpeedMbps")) / 1000
                    if f(drive.get("InterfaceSpeedMbps"))
                    else None,
                    dst.get("Health"),
                    dst.get("State"),
                    None,
                    life_left(
                        drive.get("SSDEnduranceUtilizationPercentage"),
                        consumed=True,
                    ),
                    seriale,
                    # Il valore grezzo si conserva anche quando supera 100:
                    # vuol dire durata nominale superata (o contatore
                    # inattendibile) e va mostrato, non nascosto.
                    f(drive.get("SSDEnduranceUtilizationPercentage")),
                    i(drive.get("PowerOnHours")),
                ),
            )
        return trovati

    # Senza nulla dall'elenco standard (iLO 4) SmartStorage e' l'unica
    # fonte, e "in piu'" sarebbe fuorviante.
    unica_fonte = not any(visti[k] for k in ("ctrl", "disco", "vol", "vol_dim"))

    for c_index, ref in enumerate(members(root), start=1):
        controller = rf.try_get(ref.get("@odata.id", ""))
        if not controller:
            continue

        st = controller.get("Status", {})
        controller_id = "ss-" + member_key(controller, c_index, "ctrl")
        chiave = chiave_controller(controller)
        controller_nuovo = chiave not in visti["ctrl"]
        visti["ctrl"].add(chiave)

        if controller_nuovo:
            aggiunti["ctrl"] += 1
            cur.execute(
                """
                INSERT INTO storage_controllers
                (server_id, collected_at, controller_id, manufacturer, model,
                 firmware, cache_mib, health, state)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    controller_id,
                    controller.get("Manufacturer"),
                    controller.get("Model"),
                    (controller.get("FirmwareVersion", {}) or {})
                    .get("Current", {})
                    .get("VersionString")
                    if isinstance(controller.get("FirmwareVersion"), dict)
                    else controller.get("FirmwareVersion"),
                    f(controller.get("CacheMemorySizeMiB")),
                    st.get("Health"),
                    st.get("State"),
                ),
            )

        base = str(ref.get("@odata.id", "")).rstrip("/")

        leggi_dischi(base + "/DiskDrives/", "ss-" + str(c_index) + "-")

        volumes = rf.try_get(base + "/LogicalDrives/") or {}
        for v_index, v_ref in enumerate(members(volumes), start=1):
            volume = rf.try_get(v_ref.get("@odata.id", ""))
            if not volume:
                continue
            vst = volume.get("Status", {})
            raid = volume.get("Raid")
            uid = str(volume.get("VolumeUniqueIdentifier") or "").strip()
            capacita = mib_to_bytes(volume.get("CapacityMiB"))
            if volume_gia_visto(visti, uid, raid_norm(raid), capacita):
                continue
            aggiunti["vol"] += 1
            cur.execute(
                """
                INSERT INTO storage_volumes
                (server_id, collected_at, volume_id, name, raid_type,
                 capacity_bytes, health, state)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id,
                    collected,
                    "ss-" + str(c_index) + "-" + member_key(volume, v_index, "volume"),
                    volume.get("LogicalDriveName") or volume.get("Name"),
                    f"RAID{raid}" if raid is not None else None,
                    mib_to_bytes(volume.get("CapacityMiB")),
                    vst.get("Health"),
                    vst.get("State"),
                ),
            )

    # Controller SATA integrati in modalita' AHCI: i dischi compaiono
    # qui solo se il sistema operativo ha l'Agentless Management
    # Service. Il controller si registra solo se ha dischi, altrimenti
    # sarebbe una riga vuota in piu' per ogni server.
    hba = rf.try_get("/Systems/1/SmartStorage/HostBusAdapters/", quiet=True) or {}
    for h_index, ref in enumerate(members(hba), start=1):
        adattatore = rf.try_get(ref.get("@odata.id", ""), quiet=True)
        if not adattatore:
            continue
        base = str(ref.get("@odata.id", "")).rstrip("/")
        if not leggi_dischi(base + "/DiskDrives/", "hba-" + str(h_index) + "-"):
            continue
        chiave = chiave_controller(adattatore)
        if chiave in visti["ctrl"]:
            continue
        visti["ctrl"].add(chiave)
        aggiunti["ctrl"] += 1
        hst = adattatore.get("Status") or {}
        cur.execute(
            """
            INSERT INTO storage_controllers
            (server_id, collected_at, controller_id, manufacturer, model,
             firmware, cache_mib, health, state)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                server_id,
                collected,
                "hba-" + member_key(adattatore, h_index, "ctrl"),
                None,
                adattatore.get("Model"),
                None,
                None,
                hst.get("Health"),
                hst.get("State"),
            ),
        )

    vite = aggiunti.pop("vita", 0)
    if any(aggiunti.values()):
        log(
            f"    SmartStorage: {aggiunti['disco']} dischi, "
            f"{aggiunti['vol']} volumi, {aggiunti['ctrl']} controller"
            + ("" if unica_fonte else " in piu' rispetto all'elenco standard")
        )
    if vite:
        log(f"    SmartStorage: vita residua recuperata per {vite} SSD")


def read_setting(cur, key, default):
    try:
        cur.execute(
            "SELECT setting_value FROM settings WHERE setting_key=%s", (key,)
        )
        row = cur.fetchone()
        if row and row[0] is not None:
            return row[0]
    except Exception:
        pass
    return default


def collect_logs(rf, cur, server_id, log):
    """Importa gli eventi da tutti i log esposti dall'iLO.

    Non ci fermiamo a /Managers/1/LogServices/IEL/: elenchiamo i
    servizi di log del manager e del sistema, cosi' prendiamo sia
    l'IEL (accessi e configurazione dell'iLO) sia l'IML (eventi
    hardware), il cui percorso e nome cambiano fra le generazioni.
    """
    total = 0
    skipped = 0
    ignora_accessi = str(
        read_setting(cur, "ignore_login_events", "1")
    ).strip() not in ("0", "false", "no")

    for base in ("/Managers/1/LogServices/", "/Systems/1/LogServices/"):
        collection = rf.try_get(base)
        if not collection:
            continue

        for ref in members(collection):
            uri = ref.get("@odata.id")
            if not uri:
                continue

            source = str(uri).rstrip("/").rsplit("/", 1)[-1].upper()[:20]
            entries = all_members(rf, uri.rstrip("/") + "/Entries/")
            if not entries:
                continue

            imported = 0
            for index, entry in enumerate(entries, start=1):
                # Alcune generazioni restituiscono solo i riferimenti:
                # in quel caso la voce va letta singolarmente.
                if "Message" not in entry and "Created" not in entry:
                    detail = rf.try_get(entry.get("@odata.id", ""))
                    if not detail:
                        continue
                    entry = detail

                if ignora_accessi and is_login_event(
                    entry.get("MessageId") or entry.get("MessageID"),
                    entry.get("Message"),
                ):
                    skipped += 1
                    continue

                if store_event(cur, server_id, source, entry, index):
                    imported += 1

            if imported:
                log(f"    {source}: {imported} eventi")
            total += imported

    if skipped:
        log(f"    ignorati {skipped} eventi di accesso all'iLO")

    return total


def store_event(cur, server_id, source, entry, index):
    """Salva una voce di log. Restituisce True se e' stata scritta."""
    hpe_entry = oem(entry)

    # HPE mette il numero progressivo dentro l'estensione OEM, non a
    # livello superiore. Senza un identificativo stabile la chiave
    # unica non scatta e ogni raccolta reinserisce l'intero log.
    number = i(hpe_entry.get("EventNumber"))
    if number is None:
        number = i(entry.get("EventNumber"))
    if number is None:
        number = i(entry.get("Id"))
    if number is None:
        number = i(str(entry.get("@odata.id", "")).rstrip("/").rsplit("/", 1)[-1])
    if number is None:
        number = index

    # Il campo Severity di primo livello vale OK/Warning/Critical,
    # mentre quello OEM distingue anche gli eventi informativi.
    severity = hpe_entry.get("Severity") or entry.get("Severity")
    severity = SEVERITY_MAP.get(str(severity or "").strip().lower(), severity)

    created = parse_redfish_time(
        entry.get("Created") or hpe_entry.get("Created")
    )

    message = entry.get("Message")
    if not message:
        message = entry.get("EntryType") or entry.get("Name")

    cur.execute(
        """
        INSERT INTO ilo_events
        (server_id, log_source, event_number, event_created, severity,
         message_id, message, raw_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
            event_created=VALUES(event_created),
            severity=VALUES(severity),
            message_id=VALUES(message_id),
            message=VALUES(message),
            raw_json=VALUES(raw_json)
        """,
        (
            server_id,
            source,
            number,
            created,
            severity,
            entry.get("MessageId") or entry.get("MessageID"),
            message,
            json.dumps(entry, ensure_ascii=False),
        ),
    )
    return True


def fetch_servers(db, server_id=None, include_disabled=False):
    with db.cursor(pymysql.cursors.DictCursor) as cur:
        sql = "SELECT * FROM servers WHERE 1=1"
        args = []
        if server_id is not None:
            sql += " AND id=%s"
            args.append(server_id)
        elif not include_disabled:
            sql += " AND enabled=1"
        sql += " ORDER BY name"
        cur.execute(sql, args)
        return cur.fetchall()


def collect_one(server_id, verbose=True, full=False):
    """Raccoglie un singolo server. Usata anche dall'API."""
    db = db_connect()
    try:
        rows = fetch_servers(db, server_id=server_id)
        if not rows:
            raise RuntimeError(f"Server id={server_id} non trovato")
        return collect_server(rows[0], db, verbose=verbose, full=full)
    finally:
        db.close()


def collect_all(verbose=True, full=False):
    """Raccoglie tutti i server abilitati. Restituisce l'elenco dei risultati."""
    db = db_connect()
    results = []
    try:
        servers = fetch_servers(db)
        if verbose:
            print("=" * 66)
            print(f"COLLECTOR REDFISH - {len(servers)} server abilitati")
            print("=" * 66)
        for server in servers:
            try:
                results.append(
                    collect_server(server, db, verbose=verbose, full=full)
                )
            except Exception as exc:
                # collect_server gestisce gia' i propri errori; questo e'
                # solo per problemi imprevisti (es. password non decifrabile).
                message = str(exc)[:1000]
                with db.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE servers
                        SET last_collect_status='ERROR',
                            last_collect_at=%s,
                            last_error=%s
                        WHERE id=%s
                        """,
                        (now(), message, server["id"]),
                    )
                db.commit()
                results.append(
                    {
                        "server_id": server["id"],
                        "name": server["name"],
                        "status": "ERROR",
                        "error": message,
                    }
                )
    finally:
        db.close()

    if verbose:
        ok = sum(1 for r in results if r["status"] == "OK")
        print("")
        print("=" * 66)
        print(f"COMPLETATO - {ok}/{len(results)} server raccolti senza errori")
        print("=" * 66)
    return results


def purge_old_data(days=None):
    """Elimina le rilevazioni piu' vecchie della retention configurata.

    Cancella a blocchi invece che con una sola DELETE per tabella:
    una cancellazione lunga tiene aperta la transazione mentre altri
    processi scrivono, e su tabelle grandi puo' finire in conflitto.
    Un errore su una tabella non ferma le altre, e non fa fallire la
    raccolta che e' gia' andata a buon fine.
    """
    db = db_connect()
    deleted = 0
    try:
        with db.cursor() as cur:
            if days is None:
                cur.execute(
                    "SELECT setting_value FROM settings "
                    "WHERE setting_key='retention_days'"
                )
                row = cur.fetchone()
                days = int(row[0]) if row and row[0] else 90
            if days <= 0:
                return 0

            tabelle = [
                ("system_metrics", "collected_at"),
                ("power_metrics", "collected_at"),
                ("power_supplies", "collected_at"),
                ("thermal_sensors", "collected_at"),
                ("fans", "collected_at"),
                ("processors", "collected_at"),
                ("memory_modules", "collected_at"),
                ("storage_controllers", "collected_at"),
                ("physical_drives", "collected_at"),
                ("storage_volumes", "collected_at"),
                ("network_interfaces", "collected_at"),
                ("raw_snapshots", "collected_at"),
                ("collection_runs", "started_at"),
            ]

            for table, column in tabelle:
                try:
                    while True:
                        cur.execute(
                            f"DELETE FROM {table} "
                            f"WHERE {column} < NOW() - INTERVAL %s DAY "
                            f"LIMIT 2000",
                            (days,),
                        )
                        righe = cur.rowcount
                        db.commit()
                        deleted += righe
                        if righe < 2000:
                            break
                except Exception as exc:
                    db.rollback()
                    print(f"    pulizia di {table} non riuscita: {exc}")

        return deleted
    finally:
        db.close()


class Tee:
    """Scrive contemporaneamente a video e su file."""

    def __init__(self, stream, handle):
        self.stream = stream
        self.handle = handle

    def write(self, text):
        self.stream.write(text)
        self.handle.write(text)
        return len(text)

    def flush(self):
        self.stream.flush()
        self.handle.flush()


LOG_DIR = os.path.join(BASE_DIR, "logs")
MAX_RUN_LOGS = 20
# Il lock vive in config/, non in logs/: con Docker quella cartella e'
# l'unico volume condiviso fra il contenitore dell'interfaccia e quello
# del collector, e senza condivisione le due raccolte potrebbero
# partire insieme senza vedersi.
LOCK_PATH = os.path.join(BASE_DIR, "config", "collector.lock")


@contextlib.contextmanager
def run_lock(wait_seconds=0):
    """Impedisce che due raccolte girino insieme.

    Senza questo, una raccolta manuale lanciata mentre scatta il
    timer systemd interroga gli stessi iLO in parallelo: le due
    sessioni Redfish si sovrascrivono a vicenda e le scritture sulle
    stesse tabelle possono entrare in conflitto. Chi arriva secondo
    esce subito, senza errore: la raccolta la fara' l'altro.
    """
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    handle = open(LOCK_PATH, "w")
    try:
        scadenza = time.monotonic() + max(0, wait_seconds)
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= scadenza:
                    yield False
                    return
                time.sleep(2)
        handle.write(str(os.getpid()))
        handle.flush()
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


def prune_run_logs():
    """Tiene solo gli ultimi file di raccolta, per non riempire logs/."""
    try:
        files = sorted(
            (
                os.path.join(LOG_DIR, n)
                for n in os.listdir(LOG_DIR)
                if n.startswith("raccolta-") and n.endswith(".log")
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        for path in files[MAX_RUN_LOGS:]:
            os.remove(path)
    except Exception:
        pass


def esplora_sottoalbero(rf, radice, fh, limite=150):
    """Scrive su fh ogni risorsa raggiungibile sotto radice."""
    prefisso = "/redfish/v1" + radice.rstrip("/")
    da_leggere = [radice]
    visti = set()
    letti = 0

    def collegamenti(nodo):
        if isinstance(nodo, dict):
            for chiave, valore in nodo.items():
                if chiave in ("@odata.id", "href") and isinstance(valore, str):
                    yield valore
                else:
                    yield from collegamenti(valore)
        elif isinstance(nodo, list):
            for valore in nodo:
                yield from collegamenti(valore)

    while da_leggere and letti < limite:
        percorso = da_leggere.pop(0)
        normale = percorso.replace("/redfish/v1", "").rstrip("/") + "/"
        if normale in visti:
            continue
        visti.add(normale)
        fh.write("=" * 70 + "\n" + normale + "\n" + "=" * 70 + "\n")
        try:
            payload = rf.get(normale)
            letti += 1
            fh.write(json.dumps(payload, indent=1, ensure_ascii=False))
        except Exception as exc:
            fh.write(f"NON DISPONIBILE: {exc}")
            payload = None
        fh.write("\n\n")
        for link in collegamenti(payload):
            # Solo dentro il sottoalbero: i link "Links" portano anche
            # a Chassis e Systems, che non servono qui.
            completo = link if link.startswith("/redfish/v1") else "/redfish/v1" + link
            if completo.rstrip("/").startswith(prefisso):
                da_leggere.append(completo)
    return letti


def dump_server(server_id, path):
    """Salva su file le risposte grezze dell'iLO.

    Serve per capire come un firmware struttura l'albero Redfish
    quando qualcosa non viene raccolto: il file si puo' allegare
    a una segnalazione senza doverlo copiare a pezzi.
    """
    db = db_connect()
    try:
        rows = fetch_servers(db, server_id=server_id)
        if not rows:
            print(f"Server id={server_id} non trovato")
            return 1
        server = rows[0]
    finally:
        db.close()

    password = decrypt(server.get("ilo_password_enc"))
    if not password:
        print("Password iLO non configurata per questo server")
        return 1

    if str(server.get("ilo_protocol") or "").lower() == "ribcl":
        try:
            from app import ribcl
        except ImportError:
            import ribcl
        return ribcl.prova(server["ilo_ip"], server.get("ilo_user")
                           or "Administrator", password, path)

    endpoints = [
        "/",
        "/Systems/1/",
        "/Managers/1/",
        "/Chassis/1/",
        "/Chassis/1/Power/",
        "/Chassis/1/Thermal/",
        "/Systems/1/Processors/",
        "/Systems/1/Memory/",
        "/Systems/1/EthernetInterfaces/",
        "/Managers/1/LogServices/",
        "/Systems/1/LogServices/",
        "/Managers/1/LogServices/IEL/Entries/",
        "/Systems/1/LogServices/IML/Entries/",
    ]

    ip = server["ilo_ip"]
    rf = Redfish(ip, server["ilo_user"], password)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# diagnostica Redfish - {server['name']} ({ip})\n")
            fh.write(f"# {datetime.now().isoformat(timespec='seconds')}\n\n")
            for endpoint in endpoints:
                fh.write("=" * 70 + "\n")
                fh.write(endpoint + "\n")
                fh.write("=" * 70 + "\n")
                try:
                    payload = rf.get(endpoint)
                    fh.write(json.dumps(payload, indent=1, ensure_ascii=False))
                except Exception as exc:
                    fh.write(f"NON DISPONIBILE: {exc}")
                fh.write("\n\n")
                print(f"  letto {endpoint}")

            # Lo storage si esplora per intero: controller, dischi e
            # volumi stanno due o tre livelli sotto l'elenco, ed e' li'
            # che le generazioni di iLO differiscono di piu'.
            for radice in ("/Systems/1/Storage/", "/Systems/1/SmartStorage/"):
                letti = esplora_sottoalbero(rf, radice, fh)
                if letti:
                    print(f"  letto {radice} e {letti - 1} risorse sottostanti")
                else:
                    print(f"  {radice} non disponibile su questo iLO")
    finally:
        rf.close()

    print(f"\nDiagnostica salvata in {path}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Collector Redfish per server HPE con iLO"
    )
    parser.add_argument(
        "--server", type=int, help="raccoglie solo il server con questo id"
    )
    parser.add_argument(
        "--list", action="store_true", help="elenca i server configurati"
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="elimina le rilevazioni oltre la retention e termina",
    )
    parser.add_argument(
        "--dump",
        type=int,
        metavar="ID",
        help="salva su file le risposte grezze dell'iLO di questo server",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="rilegge subito anche inventario e log, senza attendere "
             "l'intervallo configurato",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=0,
        metavar="SECONDI",
        help="se un'altra raccolta e' in corso, attende invece di uscire",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="non salvare l'output su file",
    )
    args = parser.parse_args()

    if args.list:
        db = db_connect()
        try:
            for s in fetch_servers(db, include_disabled=True):
                stato = "abilitato" if s["enabled"] else "disabilitato"
                print(
                    f"{s['id']:>4}  {s['name']:<22} {s['ilo_ip']:<16} "
                    f"{stato:<12} {s.get('last_collect_status') or '-'}"
                )
        finally:
            db.close()
        return 0

    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if args.dump:
        return dump_server(
            args.dump, os.path.join(LOG_DIR, f"diagnostica-{stamp}.txt")
        )

    # L'output di una raccolta e' lungo: lo duplichiamo su file cosi'
    # si puo' allegare invece di copiarlo dal terminale.
    handle = None
    original = sys.stdout
    log_path = os.path.join(LOG_DIR, f"raccolta-{stamp}.log")

    # Solo le esecuzioni interattive creano un file: quando gira il
    # timer systemd l'output finisce gia' in collector.log, e un file
    # per ogni raccolta ne produrrebbe centinaia al giorno.
    interattivo = False
    try:
        interattivo = sys.stdout.isatty()
    except Exception:
        interattivo = False

    if interattivo and not args.no_log:
        prune_run_logs()
        try:
            handle = open(log_path, "w", encoding="utf-8")
            sys.stdout = Tee(original, handle)
        except Exception as exc:
            print(f"Impossibile scrivere {log_path}: {exc}")
            handle = None

    try:
        if args.purge:
            print(f"Righe eliminate: {purge_old_data()}")
            return 0

        with run_lock(wait_seconds=args.wait) as ottenuto:
            if not ottenuto:
                print(
                    "Un'altra raccolta e' gia' in corso (di solito il timer "
                    "systemd). Opzioni:\n"
                    "  --wait 600                        attende fino a 10 min\n"
                    "  systemctl stop "
                    "ilo-monitor-collector.timer   sospende il timer"
                )
                return 0

            if args.server:
                result = collect_one(args.server, full=args.full)
                return 0 if result["status"] == "OK" else 1

            results = collect_all(full=args.full)
            purge_old_data()
            return 0 if all(r["status"] == "OK" for r in results) else 1
    finally:
        if handle:
            sys.stdout = original
            handle.close()
            print(f"\nOutput salvato in {log_path}")


if __name__ == "__main__":
    sys.exit(main())
