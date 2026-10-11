"""Valutazione degli avvisi e invio delle email.

Due sorgenti, indipendenti fra loro:

  - le voci del log iLO, filtrate per gravita' e per categoria;
  - lo stato dei componenti (temperature, dischi, alimentatori,
    ventole, raggiungibilita'), che viene confrontato con l'ultima
    lettura in modo da avvisare al cambiamento e non a ogni raccolta.

L'invio e' immediato: l'email parte al termine della raccolta del
server che ha generato l'evento.
"""

from datetime import datetime, timezone

import pymysql

try:
    from app.mailer import MailError, send_mail
except ImportError:  # esecuzione diretta dalla cartella app/
    from mailer import MailError, send_mail


ORDINE_GRAVITA = {"informational": 0, "warning": 1, "critical": 2}

# Parole che ricondurre una voce di log a una categoria. L'ordine
# conta: la prima categoria che trova corrispondenza vince, quindi le
# piu' specifiche stanno prima.
CATEGORIE = [
    ("storage", (
        "drive", "disk", "logical", "array", "raid", "smart storage",
        "controller", "ssd", "hdd", "backplane", "cache module",
    )),
    ("fans", ("fan", "ventola", "ventilation")),
    ("thermal", (
        "temperature", "thermal", "overheat", "inlet", "ambient",
        "cooling",
    )),
    ("power", (
        "power supply", "psu", "power", "voltage", "battery",
        "redundancy", "watt",
    )),
    ("memory", ("dimm", "memory", "ecc", "correctable")),
    ("cpu", ("processor", "cpu", "socket")),
    ("network", (
        "nic", "network", "ethernet", "link down", "link up", "port",
    )),
]


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def categoria_evento(message, message_id=None):
    """Categoria di una voce di log, 'other' se nessuna corrisponde."""
    testo = f"{message or ''} {message_id or ''}".lower()
    for nome, parole in CATEGORIE:
        if any(parola in testo for parola in parole):
            return nome
    return "other"


def gravita_sufficiente(severity, minima):
    """Vero se la gravita' dell'evento raggiunge la soglia impostata."""
    livello = ORDINE_GRAVITA.get(str(severity or "").strip().lower(), 0)
    soglia = ORDINE_GRAVITA.get(str(minima or "critical").strip().lower(), 2)
    return livello >= soglia


def regola_per_server(cur, server_id):
    """Regola di avviso del server, creata con i valori predefiniti
    se non esiste ancora."""
    cur.execute(
        "SELECT * FROM server_alerts WHERE server_id=%s", (server_id,)
    )
    riga = cur.fetchone()
    if riga:
        return riga

    cur.execute(
        "INSERT IGNORE INTO server_alerts (server_id) VALUES (%s)",
        (server_id,),
    )
    cur.execute(
        "SELECT * FROM server_alerts WHERE server_id=%s", (server_id,)
    )
    return cur.fetchone()


def categoria_attiva(regola, categoria):
    return bool(regola.get(f"cat_{categoria}", 0))


def leggi_impostazioni(cur):
    cur.execute("SELECT setting_key, setting_value FROM settings")
    return {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}


# ================================================================
# CAMBIAMENTI DI STATO DEI COMPONENTI
# ================================================================


def stato_precedente(cur, server_id, kind, item_key):
    cur.execute(
        "SELECT state FROM alert_state "
        "WHERE server_id=%s AND kind=%s AND item_key=%s",
        (server_id, kind, item_key),
    )
    riga = cur.fetchone()
    return riga["state"] if riga else None


def salva_stato(cur, server_id, kind, item_key, state):
    cur.execute(
        """
        INSERT INTO alert_state (server_id, kind, item_key, state, updated_at)
        VALUES (%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE state=VALUES(state),
                                updated_at=VALUES(updated_at)
        """,
        (server_id, kind, item_key, state, now()),
    )


def stato_sano(valore):
    return str(valore or "").strip().lower() in ("ok", "enabled", "")


def controlla_componenti(cur, server_id, regola, soglie):
    """Confronta lo stato attuale dei componenti con quello noto.

    Restituisce l'elenco degli avvisi da mandare. Il primo passaggio
    su un server registra soltanto lo stato, senza inviare nulla:
    altrimenti all'attivazione arriverebbe un'email per ogni
    componente gia' in allarme da tempo.
    """
    avvisi = []
    primo_giro = not stato_precedente(cur, server_id, "meta", "inizializzato")

    def confronta(kind, chiave, stato, descrizione, categoria):
        precedente = stato_precedente(cur, server_id, kind, chiave)
        salva_stato(cur, server_id, kind, chiave, stato)
        if primo_giro or precedente == stato:
            return
        if stato_sano(stato) and precedente is not None:
            avvisi.append({
                "categoria": categoria,
                "gravita": "Informational",
                "titolo": f"{descrizione}: tornato a {stato}",
            })
        elif not stato_sano(stato):
            avvisi.append({
                "categoria": categoria,
                "gravita": "Critical",
                "titolo": f"{descrizione}: {stato}",
            })

    # ---- dischi ----
    if regola["alert_drives"]:
        cur.execute(
            """
            SELECT d.* FROM physical_drives d
            JOIN (
                SELECT COALESCE(source, 'ilo') AS src, MAX(collected_at) AS ultimo
                FROM physical_drives WHERE server_id=%s
                GROUP BY COALESCE(source, 'ilo')
            ) u ON u.src = COALESCE(d.source, 'ilo') AND u.ultimo = d.collected_at
            WHERE d.server_id=%s
              AND (COALESCE(d.source, 'ilo') = 'ilo'
                   OR d.collected_at >= UTC_TIMESTAMP() - INTERVAL 2 DAY)
            ORDER BY COALESCE(d.source, 'ilo')
            """,
            (server_id, server_id),
        )
        # Lo stesso disco puo' arrivare dall'iLO e da Windows: si valuta una volta.
        visti_sn = set()
        for disco in cur.fetchall():
            sn = str(disco.get("serial_number") or "").strip().upper()
            if sn:
                if sn in visti_sn:
                    continue
                visti_sn.add(sn)
            chiave = str(disco["drive_id"])
            etichetta = disco.get("bay") or chiave
            stato = str(disco.get("health") or "sconosciuto")
            if disco.get("failure_predicted"):
                stato = "guasto previsto"
            vita = disco.get("media_life_left_percent")
            if vita is not None and float(vita) <= 10:
                stato = f"vita residua {int(float(vita))}%"
            errori = disco.get("uncorrected_errors")
            if errori and stato_sano(stato):
                stato = f"errori non corretti: {int(errori)}"
            confronta(
                "drive", chiave, stato,
                f"Disco {etichetta} ({disco.get('model') or '—'})",
                "storage",
            )

    # ---- alimentatori e ventole ----
    if regola["alert_psu_fans"]:
        cur.execute(
            """
            SELECT p.* FROM power_supplies p
            JOIN (SELECT MAX(collected_at) AS ultimo FROM power_supplies
                   WHERE server_id=%s) u ON u.ultimo=p.collected_at
            WHERE p.server_id=%s
            """,
            (server_id, server_id),
        )
        for psu in cur.fetchall():
            # Alloggiamento vuoto: non e' un guasto, e una ventola o un
            # alimentatore che non c'e' non deve generare email.
            if str(psu.get("state") or "").lower() == "absent":
                continue
            confronta(
                "psu", str(psu["psu_id"]),
                str(psu.get("health") or "sconosciuto"),
                f"Alimentatore {psu['psu_id']}", "power",
            )

        cur.execute(
            """
            SELECT f.* FROM fans f
            JOIN (SELECT MAX(collected_at) AS ultimo FROM fans
                   WHERE server_id=%s) u ON u.ultimo=f.collected_at
            WHERE f.server_id=%s
            """,
            (server_id, server_id),
        )
        for fan in cur.fetchall():
            if str(fan.get("state") or "").lower() == "absent":
                continue
            confronta(
                "fan", str(fan["fan_id"]),
                str(fan.get("health") or "sconosciuto"),
                f"Ventola {fan.get('fan_name') or fan['fan_id']}", "fans",
            )

    # ---- temperature ----
    if regola["alert_temperature"]:
        critica = float(soglie.get("temp_critical_c", 70) or 70)
        cur.execute(
            """
            SELECT t.* FROM thermal_sensors t
            JOIN (SELECT MAX(collected_at) AS ultimo FROM thermal_sensors
                   WHERE server_id=%s) u ON u.ultimo=t.collected_at
            WHERE t.server_id=%s AND t.temperature_c IS NOT NULL
            """,
            (server_id, server_id),
        )
        for sensore in cur.fetchall():
            valore = float(sensore["temperature_c"])
            # La soglia dell'iLO, quando c'e', e' piu' attendibile
            # della nostra impostazione generale.
            limite = sensore.get("critical_threshold") or critica
            limite = float(limite) if limite else critica
            oltre = valore >= limite
            confronta(
                "temp", str(sensore["sensor_name"]),
                f"{int(valore)} °C oltre soglia" if oltre else "nella norma",
                f"Sensore {sensore['sensor_name']}", "thermal",
            )

    salva_stato(cur, server_id, "meta", "inizializzato", "si")
    return avvisi


def controlla_raggiungibilita(cur, server, regola):
    """Avvisa quando un server smette di rispondere, e quando torna."""
    if not regola["alert_unreachable"]:
        return []

    server_id = server["id"]
    stato = "non raggiungibile" if server.get(
        "last_collect_status"
    ) == "ERROR" else "raggiungibile"

    precedente = stato_precedente(cur, server_id, "reach", "server")
    salva_stato(cur, server_id, "reach", "server", stato)

    if precedente is None or precedente == stato:
        return []

    if stato == "non raggiungibile":
        return [{
            "categoria": "other",
            "gravita": "Critical",
            "titolo": "Il server non risponde alla raccolta",
            "dettaglio": server.get("last_error") or "",
        }]
    return [{
        "categoria": "other",
        "gravita": "Informational",
        "titolo": "Il server risponde di nuovo",
    }]


# ================================================================
# EVENTI DI LOG
# ================================================================


def eventi_da_segnalare(cur, server_id, regola, limite):
    """Voci di log nuove che superano i filtri impostati."""
    da_quando = regola.get("last_alert_at")

    if da_quando is None:
        # Prima attivazione: segniamo il momento e non mandiamo nulla,
        # per non spedire un'email per ogni voce gia' in archivio.
        cur.execute(
            "UPDATE server_alerts SET last_alert_at=%s WHERE server_id=%s",
            (now(), server_id),
        )
        return []

    cur.execute(
        """
        SELECT * FROM ilo_events
        WHERE server_id=%s
          AND event_created > %s
          AND event_created > NOW() - INTERVAL 2 DAY
        ORDER BY event_created
        LIMIT %s
        """,
        (server_id, da_quando, limite * 5),
    )

    selezionati = []
    for evento in cur.fetchall():
        if not gravita_sufficiente(evento.get("severity"), regola["min_severity"]):
            continue
        categoria = categoria_evento(
            evento.get("message"), evento.get("message_id")
        )
        if not categoria_attiva(regola, categoria):
            continue
        selezionati.append({
            "categoria": categoria,
            "gravita": evento.get("severity") or "Informational",
            "titolo": evento.get("message") or "(nessun messaggio)",
            "dettaglio": evento.get("message_id") or "",
            "quando": evento.get("event_created"),
        })

    cur.execute(
        "UPDATE server_alerts SET last_alert_at=%s WHERE server_id=%s",
        (now(), server_id),
    )
    return selezionati


# ================================================================
# COMPOSIZIONE E INVIO
# ================================================================

ETICHETTE = {
    "storage": "Storage", "fans": "Ventole", "thermal": "Temperature",
    "power": "Alimentazione", "memory": "Memoria", "cpu": "Processori",
    "network": "Rete", "other": "Altro",
}


def componi(server, avvisi):
    critici = [a for a in avvisi if str(a["gravita"]).lower() == "critical"]
    gravita = "CRITICO" if critici else "AVVISO"

    oggetto = (
        f"[iLO {gravita}] {server['name']} - "
        + (avvisi[0]["titolo"][:70] if len(avvisi) == 1
           else f"{len(avvisi)} segnalazioni")
    )

    righe = [
        f"Server   : {server['name']} ({server['ilo_ip']})",
        f"Modello  : {server.get('model') or '—'}",
        f"Rilevato : {now().strftime('%d/%m/%Y %H:%M')} UTC",
        "",
        "-" * 58,
    ]
    for a in avvisi:
        righe.append(f"[{a['gravita']}] {ETICHETTE.get(a['categoria'], a['categoria'])}")
        righe.append(f"  {a['titolo']}")
        if a.get("dettaglio"):
            righe.append(f"  {a['dettaglio']}")
        if a.get("quando"):
            righe.append(f"  {a['quando']}")
        righe.append("")
    righe.append("-" * 58)
    righe.append("Messaggio generato da iLO Monitor.")

    return oggetto, "\n".join(righe)


def valuta_e_invia(db, server, verbose=True):
    """Punto di ingresso: chiamato dal collector a fine raccolta.

    Restituisce il numero di avvisi inviati. Non solleva eccezioni:
    un problema di posta non deve far fallire una raccolta riuscita.
    """
    def log(msg):
        if verbose:
            print(msg)

    try:
        # Il collector usa cursori a tupla; qui leggiamo per nome di
        # colonna, quindi ne apriamo uno a dizionario esplicitamente.
        with db.cursor(pymysql.cursors.DictCursor) as cur:
            impostazioni = leggi_impostazioni(cur)
            if str(impostazioni.get("smtp_enabled") or "0") in ("0", "", "false"):
                return 0

            regola = regola_per_server(cur, server["id"])
            if not regola or not regola["enabled"]:
                return 0

            try:
                limite = int(impostazioni.get("alert_max_per_run") or 10)
            except (TypeError, ValueError):
                limite = 10

            avvisi = []
            avvisi += controlla_raggiungibilita(cur, server, regola)
            if server.get("last_collect_status") != "ERROR":
                avvisi += controlla_componenti(
                    cur, server["id"], regola, impostazioni
                )
                avvisi += eventi_da_segnalare(
                    cur, server["id"], regola, limite
                )

            if not avvisi:
                db.commit()
                return 0

            troncati = 0
            if len(avvisi) > limite:
                troncati = len(avvisi) - limite
                avvisi = avvisi[:limite]

            oggetto, corpo = componi(server, avvisi)
            if troncati:
                corpo += (
                    f"\n\nAltre {troncati} segnalazioni non incluse: "
                    f"consulta la pagina Eventi."
                )

            try:
                destinatari = send_mail(impostazioni, oggetto, corpo)
                cur.execute(
                    """
                    INSERT INTO alert_log
                    (server_id, sent_at, subject, recipients, body, status)
                    VALUES (%s,%s,%s,%s,%s,'SENT')
                    """,
                    (server["id"], now(), oggetto[:255],
                     ", ".join(destinatari)[:255], corpo),
                )
                log(f"    avviso inviato: {len(avvisi)} segnalazioni")
            except MailError as exc:
                cur.execute(
                    """
                    INSERT INTO alert_log
                    (server_id, sent_at, subject, recipients, body,
                     status, error_message)
                    VALUES (%s,%s,%s,%s,%s,'ERROR',%s)
                    """,
                    (server["id"], now(), oggetto[:255],
                     impostazioni.get("smtp_to", "")[:255], corpo, str(exc)),
                )
                log(f"    invio avviso non riuscito: {exc}")

        db.commit()
        return len(avvisi)

    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        log(f"    valutazione avvisi non riuscita: {exc}")
        return 0
