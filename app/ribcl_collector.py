"""Raccolta dati dagli iLO 2 (e 3) tramite RIBCL.

Scrive nelle stesse tabelle della raccolta Redfish, cosi' panoramica,
dischi, avvisi e report trattano questi server come gli altri. Quello
che un iLO 2 non sa (usura dei dischi, indirizzi IP del sistema,
volumi RAID) resta semplicemente vuoto.

Ogni giro fa un solo accesso all'iLO per le metriche; l'inventario e i
registri, ogni ora, ne aggiungono uno. Gli iLO 2 sono lenti (circa 5
secondi a richiesta) e registrano ogni accesso: meno ce ne sono, meglio e'.
"""

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None

import pymysql

from app import alerts
from app import ribcl
from app.crypto_util import decrypt
from app.redfish_collector import (
    SEVERITY_MAP,
    f,
    i,
    is_login_event,
    now,
    read_setting,
    watt,
)

FUSO_PREDEFINITO = "Europe/Rome"


def _quando(testo):
    """'10/12/2026 00:20' (ora dell'iLO) -> datetime senza fuso."""
    try:
        return datetime.strptime(str(testo).strip(), "%m/%d/%Y %H:%M")
    except (TypeError, ValueError):
        return None


def scarto_orologio(voci, istante_utc):
    """Differenza fra l'orologio dell'iLO e l'UTC.

    Gli iLO 2 scrivono gli orari nel fuso in cui sono impostati, senza
    dirlo. L'accesso appena fatto per leggere il registro compare in
    cima come "XML login": quell'orario e' "adesso" secondo l'iLO, e
    il confronto con l'UTC da' lo scarto (arrotondato al quarto d'ora).
    """
    ultimo = None
    for voce in voci:
        if str(voce.get("description") or "").lower().startswith("xml login"):
            t = _quando(voce.get("last"))
            if t and (ultimo is None or t > ultimo):
                ultimo = t
    if ultimo is None:
        return None
    scarto = (ultimo - istante_utc).total_seconds()
    if abs(scarto) > 14 * 3600:
        return None
    quarti = round(scarto / 900)
    return timedelta(seconds=quarti * 900)


def in_utc(testo, scarto):
    t = _quando(testo)
    if t is None:
        return None
    if scarto is not None:
        return t - scarto
    if ZoneInfo is not None:
        try:
            locale = t.replace(tzinfo=ZoneInfo(FUSO_PREDEFINITO))
            return locale.astimezone(timezone.utc).replace(tzinfo=None)
        except Exception:
            pass
    return t


def numero_evento(sorgente, voce):
    """Gli eventi RIBCL non hanno numero: ne ricaviamo uno stabile.

    L'iLO 2 raggruppa gli eventi uguali (COUNT, LAST_UPDATE): la prima
    occorrenza, la classe e il testo identificano la voce, e restano
    uguali fra una raccolta e l'altra anche quando il conteggio sale.
    """
    chiave = "|".join([
        sorgente, voce.get("initial") or "", voce.get("class") or "",
        voce.get("description") or "",
    ])
    return int(hashlib.sha1(chiave.encode("utf-8")).hexdigest()[:15], 16)


def salva_eventi(cur, server_id, sorgente, voci, scarto, ignora_accessi):
    salvati, ignorati = 0, 0
    for voce in voci:
        testo = voce.get("description") or ""
        if ignora_accessi and is_login_event(None, testo):
            ignorati += 1
            continue
        if testo.strip().lower() in ("ilo 2 event log", "integrated management log"):
            continue
        if voce.get("count", 1) > 1:
            testo = f"{testo} (ripetuto {voce['count']} volte)"
        gravita = SEVERITY_MAP.get(
            str(voce.get("severity") or "").strip().lower(), voce.get("severity"))
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
                server_id,
                sorgente,
                numero_evento(sorgente, voce),
                in_utc(voce.get("last") or voce.get("initial"), scarto),
                gravita,
                voce.get("class"),
                testo,
                json.dumps(voce, ensure_ascii=False),
            ),
        )
        salvati += 1
    return salvati, ignorati


def collect_server(server, db, verbose=True, full=False):
    server_id = server["id"]
    name = server["name"]
    ip = server["ilo_ip"]

    def log(msg):
        if verbose:
            print(msg)

    log("")
    log("-" * 66)
    log(f"{name}  ({ip})  [RIBCL]")
    log("-" * 66)

    password = decrypt(server.get("ilo_password_enc"))
    if not password:
        raise RuntimeError(
            "Password iLO non configurata: modificare il server "
            "dall'interfaccia e reinserirla."
        )

    cur = db.cursor()
    intervallo = int(read_setting(cur, "inventory_interval_minutes", 60) or 60)
    ultimo_inventario = server.get("last_inventory_at")
    fare_inventario = (
        full
        or not ultimo_inventario
        or (now() - ultimo_inventario).total_seconds() >= intervallo * 60
    )

    cur.execute(
        "INSERT INTO collection_runs (server_id, started_at, status) "
        "VALUES (%s, %s, 'RUNNING')",
        (server_id, now()),
    )
    run_id = cur.lastrowid
    db.commit()

    rib = ribcl.Ribcl(ip, server.get("ilo_user") or "Administrator", password)
    try:
        collected = now()

        # ---------- STATO E SENSORI (un solo accesso) ----------
        log("  [1/4] stato, temperature, ventole, alimentazione")
        elementi, errori = rib.leggi([
            ("SERVER_INFO", "read", [
                "<GET_HOST_POWER_STATUS/>",
                "<GET_UID_STATUS/>",
                "<GET_EMBEDDED_HEALTH/>",
                "<GET_POWER_READINGS/>",
            ]),
        ])
        for comando, errore in errori.items():
            log(f"    {comando} non disponibile: {errore}")

        salute = ribcl.parse_salute(
            ribcl.trova(elementi, "GET_EMBEDDED_HEALTH_DATA"))
        if not (salute["temps"] or salute["fans"] or salute["psus"]):
            raise ribcl.RibclError(
                "l'iLO non ha restituito lo stato dei sensori")
        potenza = ribcl.parse_potenza(ribcl.trova(elementi, "GET_POWER_READINGS"))
        accensione = ribcl.trova(elementi, "GET_HOST_POWER")
        uid = ribcl.trova(elementi, "GET_UID_STATUS")

        stato_acc = (accensione.get("HOST_POWER") or "").strip().upper() \
            if accensione is not None else ""
        stato_uid = (uid.get("UID") or "").strip().upper() if uid is not None else ""
        salute_generale = ribcl.salute_complessiva(salute["glance"])

        cur.execute(
            """
            UPDATE servers SET
                overall_health=%s, state=%s, power_state=%s,
                indicator_led=%s, last_seen=%s
            WHERE id=%s
            """,
            (
                salute_generale,
                "Enabled",
                {"ON": "On", "OFF": "Off"}.get(stato_acc),
                {"ON": "Lit", "OFF": "Off", "BLINK": "Blinking"}.get(stato_uid),
                collected,
                server_id,
            ),
        )

        # Consumi: con alimentatori che non misurano l'iLO 2 riporta 0,
        # che non e' un consumo vero (stessa regola dei server Redfish).
        cur.execute(
            """
            INSERT INTO power_metrics
            (server_id, collected_at, consumed_watts, average_watts,
             maximum_watts, minimum_watts, cpu_watts, dimm_watts,
             gpu_watts, power_capacity_watts)
            VALUES (%s,%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL)
            """,
            (
                server_id, collected,
                watt(potenza.get("present")), watt(potenza.get("average")),
                watt(potenza.get("maximum")), watt(potenza.get("minimum")),
            ),
        )

        for n, psu in enumerate(salute["psus"], start=1):
            cur.execute(
                """
                INSERT INTO power_supplies
                (server_id, collected_at, psu_id, name, capacity_watts,
                 power_input_watts, power_output_watts, health, state)
                VALUES (%s,%s,%s,%s,NULL,NULL,NULL,%s,%s)
                """,
                (
                    server_id, collected, f"psu-{n}", psu["label"],
                    ribcl.salute(psu["status"]),
                    "Absent" if ribcl.assente(psu["status"]) else "Enabled",
                ),
            )

        ambiente = None
        for n, t in enumerate(salute["temps"], start=1):
            if t["reading"] is None or ribcl.assente(t["status"]):
                continue
            luogo = t["location"] or t["label"] or f"Sensore {n}"
            if ambiente is None and str(luogo).lower() == "ambient":
                ambiente = t["reading"]
            cur.execute(
                """
                INSERT INTO thermal_sensors
                (server_id, collected_at, sensor_name, sensor_number,
                 temperature_c, health, state, warning_threshold,
                 critical_threshold, fatal_threshold)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL)
                """,
                (
                    server_id, collected,
                    # Come gli iLO piu' recenti: "01-Ambient", "02-CPU 1"...
                    f"{n:02d}-{luogo}", t["label"], f(t["reading"]),
                    ribcl.salute(t["status"]), "Enabled",
                    f(t["caution"]), f(t["critical"]),
                ),
            )

        for n, fan in enumerate(salute["fans"], start=1):
            cur.execute(
                """
                INSERT INTO fans
                (server_id, collected_at, fan_id, fan_name, status,
                 health, state, speed_percent)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    server_id, collected, f"fan-{n}",
                    fan["label"] or f"Fan {n}", fan["status"],
                    ribcl.salute(fan["status"]),
                    "Absent" if ribcl.assente(fan["status"]) else "Enabled",
                    f(fan["speed"]),
                ),
            )

        cur.execute(
            """
            INSERT INTO system_metrics
            (server_id, collected_at, cpu_utilization, cpu_power_watts,
             memory_utilization, memory_power_watts, io_bus_utilization,
             memory_bus_utilization, ambient_temperature)
            VALUES (%s,%s,NULL,NULL,NULL,NULL,NULL,NULL,%s)
            """,
            (server_id, collected, f(ambiente)),
        )

        # I dischi stanno nella stessa risposta: si aggiornano a ogni giro,
        # cosi' un disco guasto compare subito e non dopo un'ora.
        dischi = [d for d in salute["drives"] if not ribcl.assente(d["status"])]
        for d in dischi:
            prodotto = d["product"] if d["product"] not in (None, "", "N/A") else None
            cur.execute(
                """
                INSERT INTO physical_drives
                (server_id, collected_at, drive_id, bay, manufacturer,
                 model, revision, protocol, media_type, capacity_bytes,
                 rotation_rpm, negotiated_speed_gbs, health, state,
                 failure_predicted, media_life_left_percent, serial_number)
                VALUES (%s,%s,%s,%s,NULL,%s,NULL,NULL,%s,NULL,NULL,NULL,
                        %s,%s,NULL,NULL,NULL)
                """,
                (
                    server_id, collected, f"bay-{d['bay']}", d["bay"],
                    prodotto,
                    "SSD" if prodotto and "ssd" in prodotto.lower() else None,
                    ribcl.salute(d["status"]), "Enabled",
                ),
            )
        if dischi:
            log(f"    {len(dischi)} dischi")

        # ---------- INVENTARIO E REGISTRI (a cadenza ridotta) ----------
        event_count = None
        if fare_inventario:
            log("  [2/4] firmware, processori, memoria, schede di rete")
            elementi, errori = rib.leggi([
                ("RIB_INFO", "read", ["<GET_FW_VERSION/>"]),
                ("SERVER_INFO", "read", ["<GET_SERVER_NAME/>",
                                          "<GET_HOST_DATA/>"]),
            ])
            for comando, errore in errori.items():
                log(f"    {comando} non disponibile: {errore}")

            fw = ribcl.trova(elementi, "GET_FW_VERSION")
            nome_srv = ribcl.trova(elementi, "SERVER_NAME")
            host = ribcl.parse_host_data(ribcl.trova(elementi, "GET_HOST_DATA"))

            if fw is not None:
                processore = (fw.get("MANAGEMENT_PROCESSOR") or "").strip()
                m = re.search(r"(\d)", processore)
                cur.execute(
                    """
                    UPDATE servers SET ilo_version=%s, ilo_firmware=%s,
                        ilo_license=%s
                    WHERE id=%s
                    """,
                    (
                        f"iLO {m.group(1)}" if m else processore or None,
                        " ".join(x for x in (
                            (fw.get("FIRMWARE_VERSION") or "").strip(),
                            (fw.get("FIRMWARE_DATE") or "").strip()) if x) or None,
                        (fw.get("LICENSE_TYPE") or "").strip() or None,
                        server_id,
                    ),
                )

            totale_mib = sum(x["size_mb"] or 0 for x in host["memory"])
            cpu = host["processors"]
            cur.execute(
                """
                UPDATE servers SET
                    hostname=COALESCE(%s, hostname),
                    manufacturer=COALESCE(manufacturer, 'HP'),
                    model=COALESCE(%s, model),
                    serial_number=COALESCE(%s, serial_number),
                    uuid=COALESCE(%s, uuid),
                    bios_version=COALESCE(%s, bios_version),
                    processor_summary=%s, processor_count=%s, core_count=%s,
                    memory_total_gib=%s
                WHERE id=%s
                """,
                (
                    (nome_srv.get("VALUE") or "").strip() or None
                    if nome_srv is not None else None,
                    host["model"], host["serial_number"], host["uuid"],
                    host["bios"],
                    cpu[0]["model"] if cpu else None,
                    len(cpu) or None,
                    sum(c["cores"] or 0 for c in cpu) or None,
                    round(totale_mib / 1024, 2) if totale_mib else None,
                    server_id,
                ),
            )

            for c in cpu:
                cur.execute(
                    """
                    INSERT INTO processors
                    (server_id, collected_at, processor_id, socket, model,
                     manufacturer, max_speed_mhz, total_cores,
                     total_threads, health, state)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,'Enabled')
                    """,
                    (
                        server_id, collected, c["label"] or "cpu", c["label"],
                        c["model"], c["manufacturer"], i(c["speed_mhz"]),
                        c["cores"], c["threads"],
                    ),
                )
            for mem in host["memory"]:
                cur.execute(
                    """
                    INSERT INTO memory_modules
                    (server_id, collected_at, dimm_id, device_locator,
                     capacity_mib, speed_mhz, memory_type, manufacturer,
                     part_number, rank_count, health, state)
                    VALUES (%s,%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL,NULL,'Enabled')
                    """,
                    (
                        server_id, collected, mem["label"] or "dimm",
                        mem["label"], mem["size_mb"], i(mem["speed_mhz"]),
                    ),
                )
            # Gli iLO 2 conoscono solo i MAC delle schede integrate:
            # indirizzi e stato del collegamento non li vedono.
            for nic in host["nics"]:
                cur.execute(
                    """
                    INSERT INTO network_interfaces
                    (server_id, collected_at, interface_id, name, mac_address,
                     ipv4_address, link_status, interface_enabled, speed_mbps,
                     health, state)
                    VALUES (%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL,NULL,NULL)
                    """,
                    (server_id, collected, f"nic-{nic['port']}",
                     f"Porta {nic['port']}", nic["mac"]),
                )
            log(f"    {len(cpu)} processori, {len(host['memory'])} moduli "
                f"di memoria, {len(host['nics'])} schede di rete")

            log("  [3/4] registri eventi")
            # Due accessi distinti: entrambi i registri si chiamano
            # EVENT_LOG e in un unico lotto non si distinguerebbero.
            ignora_accessi = str(
                read_setting(cur, "ignore_login_events", "1")
            ).strip() not in ("0", "false", "no")
            event_count = 0
            iel = []
            try:
                el = rib.lotto([("RIB_INFO", "read", ["<GET_EVENT_LOG/>"])])
                iel = ribcl.parse_registro(ribcl.trova(el, "EVENT_LOG"))
            except ribcl.IloNonRisponde:
                raise
            except ribcl.RibclError as exc:
                log(f"    registro iLO non disponibile: {exc}")
            scarto = scarto_orologio(iel, now())
            if scarto is not None and abs(scarto.total_seconds()) >= 60:
                log(f"    orologio dell'iLO: UTC{'+' if scarto.total_seconds() >= 0 else '-'}"
                    f"{abs(scarto.total_seconds()) / 3600:g} ore")
            salvati, ignorati = salva_eventi(
                cur, server_id, "IEL", iel, scarto, ignora_accessi)
            event_count += salvati
            if salvati:
                log(f"    IEL: {salvati} eventi")
            if ignorati:
                log(f"    ignorati {ignorati} eventi di accesso all'iLO")

            try:
                el = rib.lotto([("SERVER_INFO", "read", ["<GET_EVENT_LOG/>"])])
                iml = ribcl.parse_registro(ribcl.trova(el, "EVENT_LOG"))
                salvati, _ = salva_eventi(
                    cur, server_id, "IML", iml, scarto, ignora_accessi)
                event_count += salvati
                if salvati:
                    log(f"    IML: {salvati} eventi")
            except ribcl.IloNonRisponde:
                raise
            except ribcl.RibclError as exc:
                log(f"    IML non disponibile: {exc}")

            cur.execute(
                "UPDATE servers SET last_inventory_at=%s WHERE id=%s",
                (collected, server_id),
            )
        else:
            log(f"  [2-3/4] inventario e registri saltati "
                f"(riletti ogni {intervallo} min)")

        log("  [4/4] chiusura")
        cur.execute(
            "UPDATE collection_runs SET finished_at=%s, status='OK', "
            "error_message=NULL WHERE id=%s",
            (now(), run_id),
        )
        cur.execute(
            "UPDATE servers SET last_collect_status='OK', last_collect_at=%s, "
            "last_error=NULL WHERE id=%s",
            (now(), server_id),
        )
        db.commit()

        log(f"  OK - {server.get('model') or 'iLO 2'} / salute "
            f"{salute_generale or 'n/d'} / "
            + (f"{event_count} eventi" if event_count is not None
               else "solo metriche"))
        return {
            "server_id": server_id, "name": name, "status": "OK",
            "model": server.get("model"), "health": salute_generale,
            "events": event_count, "inventory": fare_inventario,
        }

    except Exception as exc:
        db.rollback()
        message = str(exc)[:1000]
        try:
            cur.execute(
                "UPDATE collection_runs SET finished_at=%s, status='ERROR', "
                "error_message=%s WHERE id=%s",
                (now(), message, run_id),
            )
            cur.execute(
                "UPDATE servers SET last_collect_status='ERROR', "
                "last_collect_at=%s, last_error=%s WHERE id=%s",
                (now(), message, server_id),
            )
            db.commit()
        except Exception:
            db.rollback()
        log(f"  ERRORE: {message}")
        return {"server_id": server_id, "name": name, "status": "ERROR",
                "error": message}

    finally:
        try:
            with db.cursor(pymysql.cursors.DictCursor) as ac:
                ac.execute("SELECT * FROM servers WHERE id=%s", (server_id,))
                aggiornato = ac.fetchone()
            if aggiornato:
                alerts.valuta_e_invia(db, aggiornato, verbose=verbose)
        except Exception as exc:
            print(f"    avvisi non valutati: {exc}")
        cur.close()


# ---------------------------------------------------------------- azioni

AZIONI_ACCENSIONE = {
    # azione dell'interfaccia -> comando RIBCL (SERVER_INFO, write)
    "on": '<SET_HOST_POWER HOST_POWER="Yes"/>',
    "graceful_shutdown": "<PRESS_PWR_BTN/>",
    "force_off": "<HOLD_PWR_BTN/>",
    "force_restart": "<RESET_SERVER/>",
}


def accensione(server, azione):
    """Esegue un'azione di accensione; restituisce il nuovo stato."""
    comando = AZIONI_ACCENSIONE.get(azione)
    if not comando:
        raise ValueError(
            "Azione non disponibile sugli iLO 2: sono possibili "
            "accensione, spegnimento ordinato o forzato e riavvio forzato."
        )
    rib = ribcl.Ribcl(server["ilo_ip"], server["ilo_user"],
                      decrypt(server["ilo_password_enc"]))
    rib.scrivi("SERVER_INFO", comando)
    el = rib.lotto([("SERVER_INFO", "read", ["<GET_HOST_POWER_STATUS/>"])])
    stato = ribcl.trova(el, "GET_HOST_POWER")
    valore = (stato.get("HOST_POWER") or "").strip().upper() if stato is not None else ""
    return {"ON": "On", "OFF": "Off"}.get(valore)


def led_uid(server):
    """Inverte il LED di identificazione; restituisce il nuovo stato."""
    rib = ribcl.Ribcl(server["ilo_ip"], server["ilo_user"],
                      decrypt(server["ilo_password_enc"]))
    el = rib.lotto([("SERVER_INFO", "read", ["<GET_UID_STATUS/>"])])
    uid = ribcl.trova(el, "GET_UID_STATUS")
    acceso = uid is not None and (uid.get("UID") or "").strip().upper() == "ON"
    rib.scrivi("SERVER_INFO", f'<UID_CONTROL UID="{"No" if acceso else "Yes"}"/>')
    return "Off" if acceso else "Lit"
