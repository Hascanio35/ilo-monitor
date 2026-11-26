"""Server senza scheda di gestione (niente iLO ne' BMC).

Tutti i dati arrivano dallo script per Windows: dischi, sensori e
inventario. Il pannello non ha nulla da interrogare; a ogni giro del
collector controlla solo che lo script abbia inviato di recente, e
segnala il server come non raggiungibile se tace.

L'accensione passa dal Wake-on-LAN: il "magic packet" (sei byte 0xFF
seguiti da sedici ripetizioni del MAC) inviato in broadcast UDP sulla
rete del server. Arriva solo se il pannello e il server sono sulla
stessa rete, oppure se il router inoltra i broadcast diretti verso la
rete del server (di solito no).
"""

import ipaddress
import re
import socket

from app.redfish_collector import now

# Lo script invia i sensori ogni 5 minuti: tre invii mancati di fila
# vogliono dire che il server e' spento o non raggiungibile.
MINUTI_SILENZIO = 15


def normalizza_mac(valore):
    """'00-1B-21-aa:bb.cc' -> '00:1B:21:AA:BB:CC'; None se non e' un MAC."""
    cifre = re.sub(r"[^0-9A-Fa-f]", "", str(valore or ""))
    if len(cifre) != 12 or cifre in ("0" * 12, "F" * 12, "f" * 12):
        return None
    return ":".join(cifre[i:i + 2] for i in range(0, 12, 2)).upper()


def broadcast_rete(ip, prefisso=None):
    """Indirizzo di broadcast della rete del server (/24 se ignota)."""
    try:
        rete = ipaddress.ip_network(f"{ip}/{int(prefisso or 24)}", strict=False)
    except (ValueError, TypeError):
        return None
    if rete.version != 4 or rete.prefixlen >= 31:
        return None
    return str(rete.broadcast_address)


def pacchetto_magico(mac):
    cifre = bytes.fromhex(mac.replace(":", ""))
    return b"\xff" * 6 + cifre * 16


def invia_wol(mac, ip=None, broadcast=None):
    """Invia il magic packet; restituisce le destinazioni raggiunte."""
    mac = normalizza_mac(mac)
    if not mac:
        raise ValueError("indirizzo MAC per il Wake-on-LAN mancante o non valido")
    pacchetto = pacchetto_magico(mac)
    destinazioni = []
    for d in (broadcast, broadcast_rete(ip) if ip else None, "255.255.255.255"):
        if d and d not in destinazioni:
            destinazioni.append(d)
    inviati = []
    errori = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for d in destinazioni:
            for porta in (9, 7):
                try:
                    # Due volte: e' UDP, un pacchetto perso non si sa.
                    s.sendto(pacchetto, (d, porta))
                    s.sendto(pacchetto, (d, porta))
                    inviati.append(f"{d}:{porta}")
                except OSError as exc:
                    errori.append(f"{d}:{porta} ({exc})")
    if not inviati:
        raise OSError("invio non riuscito: " + "; ".join(errori))
    return mac, inviati


def collect_server(server, db, verbose=True, full=False):
    """Nessuna interrogazione: si guarda quando ha inviato lo script."""
    from app import alerts

    server_id = server["id"]
    name = server["name"]

    def log(msg):
        if verbose:
            print(msg)

    log("")
    log("-" * 66)
    log(f"{name}  ({server.get('ilo_ip')})  [solo Windows]")
    log("-" * 66)

    cur = db.cursor()
    ultimo = server.get("agent_last_at")
    adesso = now()
    if not ultimo:
        esito, errore = "ERROR", (
            "Lo script per Windows non ha ancora inviato dati: scaricalo da "
            "Azioni > Script dischi e sensori per Windows e installalo.")
    else:
        minuti = int((adesso - ultimo).total_seconds() // 60)
        if minuti > MINUTI_SILENZIO:
            esito, errore = "ERROR", (
                f"Nessun dato dallo script per Windows da {minuti} minuti: "
                f"server spento o non raggiungibile.")
        else:
            esito, errore = "OK", None

    salute = None
    if esito == "OK":
        # La salute e' la peggiore fra temperature e dischi piu' recenti.
        cur.execute(
            """
            SELECT health FROM thermal_sensors WHERE server_id=%s
              AND collected_at=(SELECT MAX(collected_at) FROM thermal_sensors
                                WHERE server_id=%s)
            UNION ALL
            SELECT health FROM physical_drives WHERE server_id=%s
              AND source='os'
              AND collected_at=(SELECT MAX(collected_at) FROM physical_drives
                                WHERE server_id=%s AND source='os')
            """,
            (server_id, server_id, server_id, server_id),
        )
        ordine = {"OK": 1, "Warning": 2, "Critical": 3}
        salute = "OK"
        for (h,) in cur.fetchall():
            if ordine.get(h, 0) > ordine.get(salute, 0):
                salute = h

    cur.execute(
        "INSERT INTO collection_runs (server_id, started_at, finished_at, "
        "status, error_message) VALUES (%s,%s,%s,%s,%s)",
        (server_id, adesso, adesso, esito, errore),
    )
    if esito == "OK":
        cur.execute(
            "UPDATE servers SET last_collect_status='OK', last_collect_at=%s, "
            "last_error=NULL, power_state='On', overall_health=%s, "
            "state='Enabled' WHERE id=%s",
            (adesso, salute, server_id),
        )
    else:
        cur.execute(
            "UPDATE servers SET last_collect_status='ERROR', last_collect_at=%s, "
            "last_error=%s, power_state=NULL WHERE id=%s",
            (adesso, errore, server_id),
        )
    db.commit()
    log(f"  {'OK' if esito == 'OK' else 'ERRORE: ' + errore}")
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
    return {"server_id": server_id, "name": name, "status": esito,
            "error": errore, "health": salute}
