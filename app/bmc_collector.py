"""Schede di gestione Redfish non HPE (BMC).

Pensato per le schede con firmware AMI MegaRAC, come l'ASUS
ASMB10-iKVM, ma usa solo Redfish standard e vale per qualunque BMC
che lo parli. Rispetto agli iLO cambia la struttura: il sistema si
chiama "Self" (o altro) invece di "1", non ci sono estensioni HPE, e
le risorse si trovano seguendo le collezioni invece di indovinarne il
percorso.

Cosa raccoglie: stato di accensione e salute, firmware della scheda,
LED, registri eventi e - se la scheda li legge - temperature, ventole
e consumi. Su schede montate su una scheda madre che il BMC non
supporta i sensori risultano tutti "Absent": in quel caso le
temperature possono arrivare dallo script per Windows.

Usa solo la libreria standard per HTTP: le schede di questo tipo
hanno spesso certificati e cifrari datati, e cosi' la diagnostica
funziona anche fuori dal pannello.
"""

import base64
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

from app.crypto_util import decrypt
from app.redfish_collector import SEVERITY_MAP, f, now, read_setting, watt

TIMEOUT = 30

# Tipi di sensore i cui eventi non sono affidabili quando la scheda
# non legge i sensori della scheda madre: l'ASMB10 su una scheda madre
# non supportata segnala a ogni accensione un guasto agli alimentatori
# (che non controlla), una "versione hardware non supportata" e soglie
# di tensione superate da sensori che non esistono. Restano gli eventi
# di sistema (accensioni, avvii, watchdog...).
EVENTI_INAFFIDABILI = {
    "power supply / converter", "version change", "voltage",
    "temperature", "fan", "current",
}

# Registri da non importare: gli accessi alla scheda, monitoraggio
# compreso, li riempirebbero di voci inutili.
REGISTRI_ESCLUSI = {"auditlog"}

# azione dell'interfaccia -> valori ResetType accettabili, in ordine
AZIONI = {
    "on": ["On", "ForceOn"],
    "graceful_shutdown": ["GracefulShutdown"],
    "force_off": ["ForceOff"],
    "graceful_restart": ["GracefulRestart"],
    "force_restart": ["ForceRestart", "PowerCycle"],
    "nmi": ["Nmi"],
}
NOMI_AZIONI = {
    "On": "accensione", "ForceOn": "accensione",
    "GracefulShutdown": "spegnimento ordinato", "ForceOff": "spegnimento forzato",
    "GracefulRestart": "riavvio ordinato", "ForceRestart": "riavvio forzato",
    "PowerCycle": "spegni e riaccendi", "Nmi": "NMI",
}


class BmcError(RuntimeError):
    pass


def _contesto_tls():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _testo(v):
    """Le schede AMI riempiono i campi sconosciuti con uno spazio."""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


class Bmc:
    """Client Redfish minimo con autenticazione Basic.

    Niente sessioni: le schede AMI ne ammettono poche e una sessione
    lasciata aperta da una raccolta interrotta occuperebbe un posto
    fino alla scadenza.
    """

    def __init__(self, host, username, password, porta=443, timeout=TIMEOUT):
        self.base = f"https://{host}:{porta}" if porta != 443 else f"https://{host}"
        self.auth = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")).decode("ascii")
        self.timeout = timeout
        self.ctx = _contesto_tls()
        self._sistema = self._manager = self._chassis = None

    # ------------------------------------------------------------ HTTP

    def _url(self, percorso):
        if percorso.startswith("http"):
            return percorso
        if not percorso.startswith("/redfish"):
            percorso = "/redfish/v1/" + percorso.lstrip("/")
        return self.base + percorso

    def richiesta(self, metodo, percorso, dati=None, intestazioni=None):
        corpo = None
        h = {"Authorization": self.auth, "Accept": "application/json",
             "OData-Version": "4.0"}
        if dati is not None:
            corpo = json.dumps(dati).encode("utf-8")
            h["Content-Type"] = "application/json"
        if intestazioni:
            h.update(intestazioni)
        req = urllib.request.Request(self._url(percorso), data=corpo,
                                     headers=h, method=metodo)
        try:
            with urllib.request.urlopen(req, context=self.ctx,
                                        timeout=self.timeout) as r:
                testo = r.read().decode("utf-8", "replace")
                return r.status, (json.loads(testo) if testo.strip() else {})
        except urllib.error.HTTPError as e:
            dettaglio = ""
            try:
                dettaglio = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            if e.code == 401:
                raise BmcError("Credenziali rifiutate (HTTP 401)") from None
            raise BmcError(f"{metodo} {percorso}: HTTP {e.code} {dettaglio}") from None
        except (urllib.error.URLError, OSError) as e:
            motivo = getattr(e, "reason", e)
            raise BmcError(f"scheda non raggiungibile: {motivo}") from None

    def get(self, percorso):
        return self.richiesta("GET", percorso)[1]

    def try_get(self, percorso):
        try:
            return self.get(percorso)
        except BmcError as e:
            if "401" in str(e) or "non raggiungibile" in str(e):
                raise
            return None

    def post(self, percorso, dati):
        return self.richiesta("POST", percorso, dati)

    def patch(self, percorso, dati, etag=None):
        h = {"If-Match": etag} if etag else None
        return self.richiesta("PATCH", percorso, dati, h)

    # ------------------------------------------------------- risorse

    def _primo(self, collezione):
        dati = self.try_get(collezione) or {}
        for m in dati.get("Members") or []:
            if isinstance(m, dict) and m.get("@odata.id"):
                return m["@odata.id"]
        return None

    @property
    def sistema(self):
        if self._sistema is None:
            self._sistema = self._primo("/redfish/v1/Systems")
            if not self._sistema:
                raise BmcError("la scheda non espone nessun sistema")
        return self._sistema

    @property
    def manager(self):
        if self._manager is None:
            self._manager = self._primo("/redfish/v1/Managers") or ""
        return self._manager or None

    @property
    def chassis(self):
        if self._chassis is None:
            self._chassis = self._primo("/redfish/v1/Chassis") or ""
        return self._chassis or None


# ================================================================
# RICONOSCIMENTO
# ================================================================


def produttore_bmc(radice, manager=None):
    """'AMI', 'Supermicro', 'Dell'... dal servizio radice."""
    v = _testo((radice or {}).get("Vendor"))
    if v:
        return v
    for fonte in (radice or {}, manager or {}):
        oem = fonte.get("Oem") or {}
        for chiave in oem:
            if chiave.lower() not in ("hp", "hpe"):
                return chiave.upper() if len(chiave) <= 4 else chiave
    return None


def e_hpe(radice):
    oem = (radice or {}).get("Oem") or {}
    return any(k.lower() in ("hp", "hpe") for k in oem)


def identita(ip, username, password):
    """Come probe() per gli iLO: verifica le credenziali e legge chi e'."""
    bmc = Bmc(ip, username, password)
    radice = bmc.get("/redfish/v1")
    if e_hpe(radice):
        raise BmcError("e' un iLO HPE, non una scheda generica")
    sistema = bmc.get(bmc.sistema)
    manager = bmc.try_get(bmc.manager) if bmc.manager else {}
    manager = manager or {}
    stato = sistema.get("Status") or {}
    cpu = sistema.get("ProcessorSummary") or {}
    mem = sistema.get("MemorySummary") or {}
    marca = produttore_bmc(radice, manager)
    return {
        "hostname": _testo(sistema.get("HostName")),
        "manufacturer": _testo(sistema.get("Manufacturer")),
        "model": _testo(sistema.get("Model")),
        "serial_number": _testo(sistema.get("SerialNumber")),
        "uuid": _testo(sistema.get("UUID")) or _testo(radice.get("UUID")),
        "bios_version": _testo(sistema.get("BiosVersion")),
        "ilo_version": f"BMC {marca}" if marca else "BMC",
        "ilo_firmware": _testo(manager.get("FirmwareVersion")),
        "ilo_license": None,
        "overall_health": stato.get("HealthRollup") or stato.get("Health"),
        "state": stato.get("State"),
        "power_state": sistema.get("PowerState"),
        "processor_model": _testo(cpu.get("Model")),
        "processor_count": cpu.get("Count") or None,
        "memory_total_gib": mem.get("TotalSystemMemoryGiB") or None,
    }


# ================================================================
# EVENTI
# ================================================================

_CAMPI_SEL = re.compile(r"\s*([A-Za-z_0-9]+)\s*:\s*([^,]*)")


def campi_sel(messaggio):
    """'Event_Type : X, Sensor_Type : Y, ' -> {'Event_Type': 'X', ...}"""
    return {k: v.strip() for k, v in _CAMPI_SEL.findall(messaggio or "")}


def _in_utc(testo):
    if not testo or not isinstance(testo, str):
        return None
    try:
        t = datetime.fromisoformat(testo.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is not None:
        t = t.astimezone(timezone.utc).replace(tzinfo=None)
    return t


def quando_evento(voce):
    """Data dell'evento in UTC.

    Le schede AMI scrivono in Created l'ora del BMC; gli eventi
    registrati prima che il BMC avesse l'ora giusta risultano del
    1980, e per quelli ripieghiamo sull'orario scritto nel messaggio.
    """
    t = _in_utc(voce.get("Created"))
    if t and t.year >= 2000:
        return t
    t2 = _in_utc(campi_sel(voce.get("Message")).get("Timestamp"))
    return t2 or t


def testo_evento(voce):
    """Il messaggio SEL delle schede AMI e' un elenco di campi IPMI:
    ne ricaviamo una frase leggibile."""
    messaggio = str(voce.get("Message") or "").strip()
    campi = campi_sel(messaggio)
    tipo_evento = campi.get("Event_Type")
    tipo_sensore = voce.get("SensorType") or campi.get("Sensor_Type")
    if tipo_evento:
        frase = f"{tipo_sensore}: {tipo_evento}" if tipo_sensore else tipo_evento
        if campi.get("Event_Dir", "").lower().startswith("deassert"):
            frase += " (rientrato)"
        numero = campi.get("Sensor_Number")
        if numero:
            frase += f" [sensore {numero}]"
        return frase
    return messaggio or voce.get("Name") or "evento"


def numero_evento(sorgente, voce):
    chiave = "|".join([sorgente, str(voce.get("Id") or ""),
                       str(voce.get("Created") or ""),
                       str(voce.get("Message") or "")])
    return int(hashlib.sha1(chiave.encode("utf-8")).hexdigest()[:15], 16)


def registri(bmc):
    """(nome, percorso Entries) di tutti i registri di sistema,
    scheda e telaio, esclusi quelli degli accessi."""
    trovati = []
    for base in (bmc.manager, bmc.sistema, bmc.chassis):
        if not base:
            continue
        risorsa = bmc.try_get(base) or {}
        coll = (risorsa.get("LogServices") or {}).get("@odata.id")
        if not coll:
            continue
        for m in (bmc.try_get(coll) or {}).get("Members") or []:
            percorso = (m or {}).get("@odata.id")
            if not percorso:
                continue
            nome = percorso.rstrip("/").split("/")[-1]
            if nome.lower() in REGISTRI_ESCLUSI:
                continue
            servizio = bmc.try_get(percorso) or {}
            voci = (servizio.get("Entries") or {}).get("@odata.id")
            if voci:
                trovati.append((nome, voci))
    return trovati


def leggi_voci(bmc, percorso, massimo=500):
    voci = []
    pagina = percorso
    while pagina and len(voci) < massimo:
        dati = bmc.try_get(pagina) or {}
        voci.extend(m for m in dati.get("Members") or [] if isinstance(m, dict))
        pagina = dati.get("Members@odata.nextLink")
    return voci


def salva_eventi(cur, server_id, sorgente, voci, sensori_affidabili):
    salvati = scartati = 0
    for voce in voci:
        tipo = str(voce.get("SensorType")
                   or campi_sel(voce.get("Message")).get("Sensor_Type") or "")
        if not sensori_affidabili and tipo.strip().lower() in EVENTI_INAFFIDABILI:
            scartati += 1
            continue
        gravita = SEVERITY_MAP.get(
            str(voce.get("Severity") or "").strip().lower(), voce.get("Severity"))
        cur.execute(
            """
            INSERT INTO ilo_events
            (server_id, log_source, event_number, event_created, severity,
             message_id, message, raw_json)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                event_created=VALUES(event_created),
                severity=VALUES(severity),
                message=VALUES(message),
                raw_json=VALUES(raw_json)
            """,
            (
                server_id, sorgente[:50], numero_evento(sorgente, voce),
                quando_evento(voce), gravita,
                (voce.get("MessageId") or voce.get("EntryType") or None),
                testo_evento(voce)[:2000],
                json.dumps(voce, ensure_ascii=False),
            ),
        )
        salvati += 1
    return salvati, scartati


# ================================================================
# SENSORI
# ================================================================


def leggi_sensori(bmc):
    """Temperature, ventole e consumi dalla risorsa Thermal/Power del
    telaio. Restituisce solo i sensori con una lettura vera."""
    esito = {"temps": [], "fans": [], "watt": None, "presenti": 0}
    if not bmc.chassis:
        return esito
    telaio = bmc.try_get(bmc.chassis) or {}
    termico = bmc.try_get((telaio.get("Thermal") or {}).get("@odata.id")
                          or bmc.chassis + "/Thermal") or {}
    for t in termico.get("Temperatures") or []:
        stato = t.get("Status") or {}
        if stato.get("State") == "Absent":
            continue
        esito["presenti"] += 1
        lettura = f(t.get("ReadingCelsius"))
        if lettura is None:
            continue
        esito["temps"].append({
            "nome": _testo(t.get("Name")) or f"Sensore {t.get('MemberId')}",
            "numero": t.get("SensorNumber"),
            "valore": lettura,
            "salute": stato.get("Health"),
            "attenzione": f(t.get("UpperThresholdNonCritical")),
            "critica": f(t.get("UpperThresholdCritical")),
            "fatale": f(t.get("UpperThresholdFatal")),
        })
    for v in termico.get("Fans") or []:
        stato = v.get("Status") or {}
        if stato.get("State") == "Absent":
            continue
        esito["presenti"] += 1
        lettura = f(v.get("Reading"))
        if lettura is None:
            continue
        unita = str(v.get("ReadingUnits") or "RPM")
        esito["fans"].append({
            "nome": _testo(v.get("Name") or v.get("FanName"))
            or f"Ventola {v.get('MemberId')}",
            "percento": lettura if unita.lower().startswith("percent") else None,
            "rpm": int(lettura) if not unita.lower().startswith("percent") else None,
            "salute": stato.get("Health"),
        })
    potenza = bmc.try_get((telaio.get("Power") or {}).get("@odata.id")
                          or bmc.chassis + "/Power") or {}
    for pc in potenza.get("PowerControl") or []:
        w = watt(pc.get("PowerConsumedWatts"))
        if w is not None:
            esito["watt"] = w
            break
    for v in potenza.get("Voltages") or []:
        if (v.get("Status") or {}).get("State") != "Absent":
            esito["presenti"] += 1
    return esito


# ================================================================
# RACCOLTA
# ================================================================


def collect_server(server, db, verbose=True, full=False):
    from app import alerts

    server_id = server["id"]
    name = server["name"]
    ip = server["ilo_ip"]

    def log(msg):
        if verbose:
            print(msg)

    log("")
    log("-" * 66)
    log(f"{name}  ({ip})  [BMC]")
    log("-" * 66)

    password = decrypt(server.get("ilo_password_enc"))
    if not password:
        raise RuntimeError(
            "Password della scheda non configurata: modificare il server "
            "dall'interfaccia e reinserirla.")

    cur = db.cursor()
    intervallo = int(read_setting(cur, "inventory_interval_minutes", 60) or 60)
    ultimo_inventario = server.get("last_inventory_at")
    fare_inventario = (
        full or not ultimo_inventario
        or (now() - ultimo_inventario).total_seconds() >= intervallo * 60
    )

    cur.execute(
        "INSERT INTO collection_runs (server_id, started_at, status) "
        "VALUES (%s, %s, 'RUNNING')", (server_id, now()))
    run_id = cur.lastrowid
    db.commit()

    bmc = Bmc(ip, server.get("ilo_user") or "admin", password)
    salute = None
    event_count = None
    try:
        collected = now()

        log("  [1/3] stato e sensori")
        sistema = bmc.get(bmc.sistema)
        manager = (bmc.try_get(bmc.manager) if bmc.manager else None) or {}
        stato = sistema.get("Status") or {}
        salute = stato.get("HealthRollup") or stato.get("Health")
        cur.execute(
            """
            UPDATE servers SET
                overall_health=%s, state=%s, power_state=%s,
                indicator_led=%s, last_seen=%s,
                ilo_firmware=COALESCE(%s, ilo_firmware),
                bios_version=COALESCE(%s, bios_version),
                manufacturer=COALESCE(%s, manufacturer),
                model=COALESCE(%s, model),
                serial_number=COALESCE(%s, serial_number)
            WHERE id=%s
            """,
            (
                salute, stato.get("State"), sistema.get("PowerState"),
                sistema.get("IndicatorLED"), collected,
                _testo(manager.get("FirmwareVersion")),
                _testo(sistema.get("BiosVersion")),
                _testo(sistema.get("Manufacturer")),
                _testo(sistema.get("Model")),
                _testo(sistema.get("SerialNumber")),
                server_id,
            ),
        )

        sensori = leggi_sensori(bmc)
        affidabili = sensori["presenti"] > 0
        for n, t in enumerate(sensori["temps"], start=1):
            cur.execute(
                """
                INSERT INTO thermal_sensors
                (server_id, collected_at, sensor_name, sensor_number,
                 temperature_c, health, state, warning_threshold,
                 critical_threshold, fatal_threshold)
                VALUES (%s,%s,%s,%s,%s,%s,'Enabled',%s,%s,%s)
                """,
                (server_id, collected, f"{n:02d}-{t['nome']}",
                 t["numero"], t["valore"], t["salute"],
                 t["attenzione"], t["critica"], t["fatale"]),
            )
        for n, v in enumerate(sensori["fans"], start=1):
            cur.execute(
                """
                INSERT INTO fans
                (server_id, collected_at, fan_id, fan_name, status,
                 health, state, speed_percent, speed_rpm)
                VALUES (%s,%s,%s,%s,NULL,%s,'Enabled',%s,%s)
                """,
                (server_id, collected, f"fan-{n}", v["nome"], v["salute"],
                 v["percento"], v["rpm"]),
            )
        if sensori["watt"] is not None:
            cur.execute(
                "INSERT INTO power_metrics (server_id, collected_at, "
                "consumed_watts) VALUES (%s,%s,%s)",
                (server_id, collected, sensori["watt"]),
            )
        if sensori["temps"] or sensori["fans"]:
            log(f"    {len(sensori['temps'])} temperature, "
                f"{len(sensori['fans'])} ventole")
        else:
            log("    la scheda non legge i sensori di questa scheda madre")

        if fare_inventario:
            log("  [2/3] registri eventi")
            event_count = 0
            for nome, percorso in registri(bmc):
                voci = leggi_voci(bmc, percorso)
                salvati, scartati = salva_eventi(
                    cur, server_id, nome, voci, affidabili)
                event_count += salvati
                if salvati or scartati:
                    log(f"    {nome}: {salvati} eventi"
                        + (f", {scartati} scartati (sensori non letti "
                           f"dalla scheda)" if scartati else ""))
            cur.execute("UPDATE servers SET last_inventory_at=%s WHERE id=%s",
                        (collected, server_id))
        else:
            log(f"  [2/3] registri saltati (riletti ogni {intervallo} min)")

        log("  [3/3] chiusura")
        cur.execute(
            "UPDATE collection_runs SET finished_at=%s, status='OK', "
            "error_message=NULL WHERE id=%s", (now(), run_id))
        cur.execute(
            "UPDATE servers SET last_collect_status='OK', last_collect_at=%s, "
            "last_error=NULL WHERE id=%s", (now(), server_id))
        db.commit()
        log(f"  OK - acceso: {sistema.get('PowerState') or 'n/d'} / salute "
            f"{salute or 'n/d'}"
            + (f" / {event_count} eventi" if event_count is not None else ""))
        return {"server_id": server_id, "name": name, "status": "OK",
                "model": server.get("model"), "health": salute,
                "events": event_count, "inventory": fare_inventario}

    except Exception as exc:
        db.rollback()
        message = str(exc)[:1000]
        try:
            cur.execute(
                "UPDATE collection_runs SET finished_at=%s, status='ERROR', "
                "error_message=%s WHERE id=%s", (now(), message, run_id))
            cur.execute(
                "UPDATE servers SET last_collect_status='ERROR', "
                "last_collect_at=%s, last_error=%s WHERE id=%s",
                (now(), message, server_id))
            db.commit()
        except Exception:
            db.rollback()
        log(f"  ERRORE: {message}")
        return {"server_id": server_id, "name": name, "status": "ERROR",
                "error": message}

    finally:
        try:
            import pymysql
            with db.cursor(pymysql.cursors.DictCursor) as ac:
                ac.execute("SELECT * FROM servers WHERE id=%s", (server_id,))
                aggiornato = ac.fetchone()
            if aggiornato:
                alerts.valuta_e_invia(db, aggiornato, verbose=verbose)
        except Exception as exc:
            print(f"    avvisi non valutati: {exc}")
        cur.close()


# ================================================================
# AZIONI
# ================================================================


def _bmc_di(server):
    return Bmc(server["ilo_ip"], server.get("ilo_user") or "admin",
               decrypt(server["ilo_password_enc"]))


def valori_reset(bmc, sistema):
    """(destinazione, valori ResetType ammessi o None se non dichiarati)."""
    azione = (sistema.get("Actions") or {}).get("#ComputerSystem.Reset") or {}
    destinazione = azione.get("target") or (
        bmc.sistema + "/Actions/ComputerSystem.Reset")
    ammessi = azione.get("ResetType@Redfish.AllowableValues")
    info = azione.get("@Redfish.ActionInfo")
    if not ammessi and info:
        dati = bmc.try_get(info) or {}
        for p in dati.get("Parameters") or []:
            if p.get("Name") == "ResetType":
                ammessi = p.get("AllowableValues")
    return destinazione, ammessi


def accensione(server, azione):
    """Esegue un'azione di accensione; restituisce (stato, ResetType)."""
    candidati = AZIONI.get(azione)
    if not candidati:
        raise ValueError(f"Azione non riconosciuta: {azione}")
    bmc = _bmc_di(server)
    sistema = bmc.get(bmc.sistema)
    destinazione, ammessi = valori_reset(bmc, sistema)
    scelto = candidati[0]
    if ammessi:
        disponibili = [c for c in candidati if c in ammessi]
        if not disponibili:
            elenco = ", ".join(NOMI_AZIONI.get(a, a) for a in ammessi)
            raise ValueError(
                f"La scheda non ammette questa azione. Ammesse: {elenco}.")
        scelto = disponibili[0]
    bmc.post(destinazione, {"ResetType": scelto})
    stato = None
    for _ in range(3):
        time.sleep(2)
        stato = (bmc.try_get(bmc.sistema) or {}).get("PowerState") or stato
    return stato, scelto


def led(server):
    """Inverte il LED di identificazione; restituisce il nuovo stato."""
    bmc = _bmc_di(server)
    ultimo_errore = None
    for percorso in (bmc.sistema, bmc.chassis):
        if not percorso:
            continue
        risorsa = bmc.get(percorso)
        if "IndicatorLED" not in risorsa:
            continue
        nuovo = "Off" if str(risorsa.get("IndicatorLED")).lower() in (
            "lit", "blinking") else "Lit"
        try:
            bmc.patch(percorso, {"IndicatorLED": nuovo},
                      etag=risorsa.get("@odata.etag"))
            return nuovo
        except BmcError as exc:
            ultimo_errore = exc
    raise ultimo_errore or BmcError("la scheda non ha un LED di identificazione")


# ================================================================
# DIAGNOSTICA
# ================================================================

SALTA = (
    "/redfish/v1/JsonSchemas", "/redfish/v1/Registries",
    "/redfish/v1/$metadata", "/redfish/v1/odata",
    "/redfish/v1/AccountService", "/redfish/v1/SessionService",
    "/redfish/v1/CertificateService", "/redfish/v1/EventService",
    "/redfish/v1/TaskService", "/redfish/v1/TelemetryService",
)


def esplora(ip, username, password, percorso_file, massimo=700, voci_log=40):
    """Salva su file l'albero Redfish della scheda (senza password)."""

    def collegamenti(obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "@odata.id" and isinstance(v, str):
                    out.append(v)
                else:
                    collegamenti(v, out)
        elif isinstance(obj, list):
            for v in obj:
                collegamenti(v, out)

    def norm(p):
        return p.split("#")[0].split("?")[0].rstrip("/") or "/"

    bmc = Bmc(ip, username, password)
    visti, coda, letti = set(), deque(["/redfish/v1"]), 0
    with open(percorso_file, "w", encoding="utf-8") as fh:
        fh.write(f"# diagnostica BMC {ip} - "
                 f"{datetime.now().isoformat(timespec='seconds')}\n\n")
        while coda and letti < massimo:
            p = norm(coda.popleft())
            if p in visti or not p.startswith("/redfish/v1"):
                continue
            visti.add(p)
            if any(p.startswith(s) for s in SALTA):
                continue
            fh.write("=" * 70 + f"\n{p}\n" + "=" * 70 + "\n")
            try:
                dati = bmc.get(p)
            except BmcError as exc:
                fh.write(f"ERRORE: {exc}\n\n")
                if "401" in str(exc):
                    raise
                continue
            letti += 1
            if p.endswith("/Entries") and isinstance(dati.get("Members"), list):
                dati["Members"] = dati["Members"][:voci_log]
                fh.write(json.dumps(dati, indent=1, ensure_ascii=False) + "\n\n")
                continue
            fh.write(json.dumps(dati, indent=1, ensure_ascii=False) + "\n\n")
            print(f"  letto {p}")
            link = []
            collegamenti(dati, link)
            coda.extend(norm(x) for x in link if norm(x) not in visti)
    print(f"Risorse lette: {letti}. File: {percorso_file}")
    return 0
