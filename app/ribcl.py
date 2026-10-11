"""Client RIBCL per gli iLO 2 (e 3), che non hanno Redfish.

RIBCL e' l'interfaccia XML che HPE usava prima di Redfish: si apre una
connessione TLS sulla 443, si invia un documento XML con credenziali e
comandi, e l'iLO risponde con una serie di documenti XML concatenati.

Gli iLO 2 parlano solo TLS 1.0 con cifrari vecchi, che OpenSSL 3 rifiuta
di default: il contesto TLS qui sotto li riabilita SOLO per queste
connessioni, il resto del sistema non cambia.

Uso da riga di comando (prova su un iLO 2, salva le risposte grezze):

    venv/bin/python -m app.ribcl --probe 192.168.1.50 --user Administrator
"""

import argparse
import getpass
import os
import re
import socket
import ssl
import sys
import time
import warnings
import xml.etree.ElementTree as ET
from datetime import datetime
from xml.sax.saxutils import quoteattr

BASE_DIR = os.getenv("ILO_MONITOR_BASE", "/opt/ilo-monitor")
LOG_DIR = os.path.join(BASE_DIR, "logs")


class RibclError(Exception):
    """Errore restituito dall'iLO o di comunicazione."""


class IloNonRisponde(RibclError):
    """L'iLO non completa nemmeno la connessione TLS.

    Gli iLO 2 hanno pochissime connessioni contemporanee: se ne restano
    di appese smettono di accettarne di nuove finche' non scadono o
    finche' l'iLO non viene riavviato.
    """


def contesto_tls_legacy():
    """TLS che accetta gli iLO 2: TLS 1.0, cifrari vecchi, niente verifica.

    Il certificato degli iLO e' autofirmato (come per Redfish, dove
    verify=False), e la rete e' quella di gestione.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            # Python avvisa che TLS 1.0 e' deprecato: lo sappiamo, e gli
            # iLO 2 non parlano altro.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    # SECLEVEL=0 riabilita chiavi e firme deboli che gli iLO 2 usano.
    try:
        # Prima i cifrari con scambio chiavi RSA: il DHE costa molto al
        # processore degli iLO 2 e allunga la connessione di parecchi
        # secondi. Gli altri restano come riserva.
        ctx.set_ciphers(
            "AES128-SHA:AES256-SHA:DES-CBC3-SHA:ALL:@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("ALL")
    # Gli iLO 2 non supportano la rinegoziazione sicura (RFC 5746):
    # OpenSSL 3 altrimenti chiude la connessione con
    # "unsafe legacy renegotiation disabled".
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


def dividi_documenti(testo):
    """La risposta e' una sequenza di documenti XML: li separa."""
    parti = re.split(r"<\?xml[^>]*\?>", testo)
    return [p.strip() for p in parti if p.strip()]


def ripulisci_xml(doc):
    """Correzioni ai difetti noti dell'XML degli iLO 2.

    Alcuni firmware mettono caratteri di controllo o '&' non escapati
    nei testi (per esempio nelle descrizioni SMBIOS).
    """
    doc = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", doc)
    doc = re.sub(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", doc)
    return doc


class Ribcl:
    def __init__(self, host, username, password, port=443, timeout=60,
                 timeout_tls=90):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout          # attesa della risposta
        # La connessione TLS di un iLO 2 puo' richiedere 20-30 secondi:
        # ha un limite suo, che la ricerca del formato non accorcia.
        self.timeout_tls = timeout_tls
        # Sessione TLS da riprendere: evita di rifare ogni volta la parte
        # lenta della connessione.
        self.sessione = None
        self.ctx = contesto_tls_legacy()
        self.ultima_tls = None
        self.protocollo = None  # modo di invio, scelto al primo comando
        self.tentativi = []     # esito di ogni modo provato, per la diagnosi

    # ---------------------------------------------------------- trasporto

    def _connetti(self):
        inizio = time.monotonic()
        try:
            grezzo = socket.create_connection(
                (self.host, self.port), self.timeout_tls)
            try:
                conn = self.ctx.wrap_socket(
                    grezzo, server_hostname=None, session=self.sessione)
            except ssl.SSLError:
                if self.sessione is None:
                    raise
                # Sessione rifiutata: connessione completa da capo.
                grezzo.close()
                self.sessione = None
                grezzo = socket.create_connection(
                    (self.host, self.port), self.timeout_tls)
                conn = self.ctx.wrap_socket(grezzo, server_hostname=None)
        except (socket.timeout, TimeoutError, ConnectionRefusedError) as exc:
            raise IloNonRisponde(
                f"l'iLO non accetta connessioni dopo "
                f"{time.monotonic() - inizio:.0f}s ({type(exc).__name__}: {exc})"
            ) from exc
        conn.settimeout(self.timeout)
        ripresa = getattr(conn, "session_reused", False)
        try:
            self.sessione = conn.session
        except (AttributeError, ValueError):
            self.sessione = None
        self.ultima_tls = (
            f"{conn.version()} / {conn.cipher()[0]}, connessione in "
            f"{time.monotonic() - inizio:.1f}s"
            + (" (sessione ripresa)" if ripresa else "")
        )
        return conn

    @staticmethod
    def _chiudi(conn):
        """Chiude avvisando l'iLO, che altrimenti tiene il posto occupato."""
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def _leggi_tutto(self, conn, completo=None, pausa=10):
        """Legge fino alla chiusura, o finche' la risposta e' completa.

        Alcuni iLO 2 non chiudono la connessione dopo aver risposto:
        aspettare la chiusura vorrebbe dire restare fermi fino al
        timeout. completo(dati) dice quando la risposta sembra finita;
        da quel momento si aspettano solo `pausa` secondi di silenzio,
        nel caso arrivi un altro pezzo.
        """
        dati = b""
        conn.settimeout(self.timeout)
        while True:
            try:
                pezzo = conn.recv(65536)
            except socket.timeout:
                break
            except (ssl.SSLError, ConnectionResetError, OSError):
                break
            if not pezzo:
                break
            dati += pezzo
            if completo and completo(dati):
                conn.settimeout(pausa)
            else:
                conn.settimeout(self.timeout)
        return dati.decode("utf-8", errors="replace")

    @staticmethod
    def _http_completo(dati):
        testa, sep, corpo = dati.partition(b"\r\n\r\n")
        if not sep:
            return False
        m = re.search(rb"content-length:\s*(\d+)", testa, re.I)
        if m:
            return len(corpo) >= int(m.group(1))
        if b"chunked" in testa.lower():
            return corpo.endswith(b"0\r\n\r\n")
        return False

    @staticmethod
    def _ribcl_completo(dati):
        return dati.rstrip().endswith(b"</RIBCL>")

    def _invia_raw(self, xml, intestazione="", per_righe=False):
        """Protocollo degli iLO 2: XML direttamente sul socket TLS.

        per_righe imita locfg.pl, lo script ufficiale HP: la
        dichiarazione XML in una scrittura a se', poi il documento una
        riga per scrittura. Il parser degli iLO 2 legge per record TLS,
        e se riceve tutto insieme risponde "syntax error near ?>".
        """
        conn = self._connetti()
        try:
            if per_righe:
                if intestazione:
                    conn.sendall(intestazione.encode("utf-8"))
                righe = re.sub(r">\s*<", ">\n<", xml).split("\n")
                for riga in righe:
                    conn.sendall((riga + "\r\n").encode("utf-8"))
            else:
                conn.sendall((intestazione + xml + "\r\n").encode("utf-8"))
            return self._leggi_tutto(conn, self._ribcl_completo)
        finally:
            self._chiudi(conn)

    def _invia_http(self, xml):
        """Protocollo degli iLO 3 e successivi: POST su /ribcl."""
        corpo = ('<?xml version="1.0"?>\r\n' + xml).encode("utf-8")
        richiesta = (
            f"POST /ribcl HTTP/1.1\r\nHost: {self.host}\r\n"
            f"Content-Type: text/xml\r\nContent-Length: {len(corpo)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii") + corpo
        conn = self._connetti()
        try:
            conn.sendall(richiesta)
            risposta = self._leggi_tutto(conn, self._http_completo, pausa=1)
        finally:
            self._chiudi(conn)
        testa, _, corpo = risposta.partition("\r\n\r\n")
        if "chunked" in testa.lower():
            corpo = self._dechunk(corpo)
        return corpo

    @staticmethod
    def _dechunk(testo):
        uscita, resto = [], testo
        while resto:
            riga, _, resto = resto.partition("\r\n")
            try:
                n = int(riga.strip() or "0", 16)
            except ValueError:
                return testo
            if n == 0:
                break
            uscita.append(resto[:n])
            resto = resto[n + 2:]
        return "".join(uscita)

    # Modi di invio, nell'ordine in cui si provano. Gli iLO 2 2.33
    # rispondono "syntax error near ?>" se ricevono la dichiarazione
    # XML davanti al comando; altri firmware la vogliono.
    MODI = {
        "raw-righe": lambda self, xml: self._invia_raw(
            xml, '<?xml version="1.0"?>\r\n', per_righe=True),
        "raw": lambda self, xml: self._invia_raw(xml),
        "raw+xml": lambda self, xml: self._invia_raw(
            xml, '<?xml version="1.0"?>\r\n'),
        "http": lambda self, xml: self._invia_http(xml),
    }

    @staticmethod
    def _accettato(testo):
        return "<RIBCL" in testo and "syntax error" not in testo.lower()

    def invia(self, xml):
        """Invia un documento RIBCL e restituisce il testo grezzo."""
        if self.protocollo:
            return self.MODI[self.protocollo](self, xml)
        # Primo invio: si prova finche' l'iLO accetta il formato, e il
        # modo che funziona si usa per tutti i comandi successivi.
        # Durante la ricerca il timeout e' breve: un formato sbagliato
        # spesso non riceve risposta e l'iLO resta in attesa.
        ultimo = ""
        self.tentativi = []
        attesa_normale, self.timeout = self.timeout, min(self.timeout, 30)
        try:
            for nome, modo in self.MODI.items():
                if self.tentativi:
                    # Un attimo di respiro: l'iLO 2 libera le connessioni
                    # lentamente.
                    time.sleep(3)
                inizio = time.monotonic()
                try:
                    testo = modo(self, xml)
                except IloNonRisponde:
                    raise
                except (OSError, ssl.SSLError) as exc:
                    testo = f"(eccezione) {type(exc).__name__}: {exc}"
                self.tentativi.append(
                    (nome, round(time.monotonic() - inizio, 1), testo))
                if self._accettato(testo):
                    self.protocollo = nome
                    return testo
                ultimo = testo
        finally:
            self.timeout = attesa_normale
        return ultimo

    # ---------------------------------------------------------- comandi

    def comando(self, sezione, modo, interno):
        """Esegue un comando: restituisce (testo grezzo, documento dati).

        sezione: SERVER_INFO, RIB_INFO, USER_INFO
        interno: XML del comando, per esempio "<GET_EMBEDDED_HEALTH/>"
        """
        xml = (
            '<RIBCL VERSION="2.0">'
            f"<LOGIN USER_LOGIN={quoteattr(self.username)} "
            f"PASSWORD={quoteattr(self.password)}>"
            f'<{sezione} MODE="{modo}">{interno}</{sezione}>'
            "</LOGIN></RIBCL>"
        )
        grezzo = self.invia(xml)
        if "<RIBCL" not in grezzo:
            raise RibclError(
                "risposta non RIBCL: " + " ".join(grezzo.split())[:200]
            )
        dati = None
        for doc in dividi_documenti(grezzo):
            try:
                radice = ET.fromstring(ripulisci_xml(doc))
            except ET.ParseError:
                continue
            for risposta in radice.iter("RESPONSE"):
                stato = risposta.get("STATUS", "0x0000")
                if int(stato, 16) != 0:
                    raise RibclError(
                        f"{stato}: {risposta.get('MESSAGE', 'errore')}"
                    )
            # Il documento dati e' quello che contiene altro oltre a RESPONSE.
            figli = [c for c in radice if c.tag != "RESPONSE"]
            if figli:
                dati = radice
        return grezzo, dati

    def lotto(self, sezioni):
        """Piu' comandi in un solo accesso all'iLO.

        sezioni: lista di (sezione, modo, [comandi XML]). Restituisce
        gli elementi dati della risposta, nell'ordine in cui arrivano.
        Un solo accesso vuol dire una sola riga "XML login" nel registro
        dell'iLO e una sola connessione TLS invece di una per comando.
        """
        corpo = "".join(
            f'<{sezione} MODE="{modo}">{"".join(comandi)}</{sezione}>'
            for sezione, modo, comandi in sezioni
        )
        xml = (
            '<RIBCL VERSION="2.0">'
            f"<LOGIN USER_LOGIN={quoteattr(self.username)} "
            f"PASSWORD={quoteattr(self.password)}>"
            f"{corpo}</LOGIN></RIBCL>"
        )
        grezzo = self.invia(xml)
        if "<RIBCL" not in grezzo:
            raise RibclError(
                "risposta non RIBCL: " + " ".join(grezzo.split())[:200]
            )
        elementi = []
        for doc in dividi_documenti(grezzo):
            try:
                radice = ET.fromstring(ripulisci_xml(doc))
            except ET.ParseError:
                continue
            for risposta in radice.iter("RESPONSE"):
                stato = risposta.get("STATUS", "0x0000")
                if int(stato, 16) != 0:
                    raise RibclError(
                        f"{stato}: {risposta.get('MESSAGE', 'errore')}"
                    )
            elementi.extend(c for c in radice if c.tag != "RESPONSE")
        return elementi

    def leggi(self, sezioni):
        """Come lotto(), ma se il lotto non passa ripiega su un comando
        alla volta. Restituisce (elementi, errori per comando)."""
        try:
            return self.lotto(sezioni), {}
        except IloNonRisponde:
            raise
        except RibclError:
            pass
        elementi, errori = [], {}
        for sezione, modo, comandi in sezioni:
            for comando in comandi:
                try:
                    elementi.extend(self.lotto([(sezione, modo, [comando])]))
                except IloNonRisponde:
                    raise
                except RibclError as exc:
                    errori[comando.strip("</>")] = str(exc)
        return elementi, errori

    def scrivi(self, sezione, comando):
        """Esegue un comando di modifica (accensione, LED...)."""
        return self.lotto([(sezione, "write", [comando])])

    def xmldata(self):
        """Pagina /xmldata?item=all: modello, seriale, firmware, senza login."""
        richiesta = (
            f"GET /xmldata?item=all HTTP/1.1\r\nHost: {self.host}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        conn = self._connetti()
        try:
            conn.sendall(richiesta)
            risposta = self._leggi_tutto(conn, self._http_completo, pausa=1)
        finally:
            self._chiudi(conn)
        testa, _, corpo = risposta.partition("\r\n\r\n")
        if "chunked" in testa.lower():
            corpo = self._dechunk(corpo)
        return corpo


# ------------------------------------------------------------------ lettura
# Funzioni pure: trasformano le risposte XML in dizionari semplici,
# cosi' si possono provare sulle risposte reali salvate dalla prova.


def valore(elemento, figlio, attributo="VALUE"):
    """<FIGLIO VALUE="x"/> dentro elemento -> "x" (spazi tolti)."""
    if elemento is None:
        return None
    nodo = elemento.find(figlio)
    if nodo is None:
        return None
    v = nodo.get(attributo)
    return v.strip() if isinstance(v, str) else v


def numero(testo):
    """'3067 MHz' -> 3067.0; 'N/A', '' o None -> None."""
    if testo is None:
        return None
    m = re.search(r"-?\d+(\.\d+)?", str(testo))
    return float(m.group(0)) if m else None


def salute(stato):
    """Stato iLO 2 ('Ok', 'Degraded', 'Failed'...) -> salute Redfish."""
    s = str(stato or "").strip().lower()
    if not s or s in ("n/a", "unknown"):
        return None
    if s == "ok":
        return "OK"
    if "fail" in s or "critical" in s:
        return "Critical"
    if "not installed" in s or "not present" in s:
        return None
    return "Warning"


def assente(stato):
    s = str(stato or "").strip().lower()
    return "not installed" in s or "not present" in s


def parse_xmldata(testo):
    """Pagina /xmldata: modello, seriale, generazione e firmware."""
    try:
        radice = ET.fromstring(ripulisci_xml(
            testo[testo.find("<RIMP"):] if "<RIMP" in testo else testo))
    except ET.ParseError:
        return {}
    def t(percorso):
        nodo = radice.find(percorso)
        return (nodo.text or "").strip() if nodo is not None and nodo.text else None
    return {
        "model": t("HSI/SPN"),
        "serial_number": t("HSI/SBSN"),
        "uuid": t("HSI/cUUID"),
        "ilo_product": t("MP/PN"),
        "ilo_firmware": t("MP/FWRI"),
    }


def generazione_da_xmldata(info):
    """'Integrated Lights-Out 2 (iLO 2)' -> 2; None se non si capisce."""
    m = re.search(r"iLO\s*(\d)", str(info.get("ilo_product") or ""))
    return int(m.group(1)) if m else None


def trova(elementi, tag):
    for e in elementi:
        if e.tag == tag:
            return e
    return None


def parse_salute(dati):
    """GET_EMBEDDED_HEALTH_DATA -> ventole, temperature, alimentatori,
    dischi e riepilogo."""
    esito = {"fans": [], "temps": [], "psus": [], "drives": [], "glance": {}}
    if dati is None:
        return esito

    for fan in dati.findall("FANS/FAN"):
        esito["fans"].append({
            "label": valore(fan, "LABEL"),
            "zone": valore(fan, "ZONE"),
            "status": valore(fan, "STATUS"),
            "speed": numero(valore(fan, "SPEED")),
        })

    for temp in dati.findall("TEMPERATURE/TEMP"):
        esito["temps"].append({
            "label": valore(temp, "LABEL"),
            "location": valore(temp, "LOCATION"),
            "status": valore(temp, "STATUS"),
            "reading": numero(valore(temp, "CURRENTREADING")),
            "caution": numero(valore(temp, "CAUTION")),
            "critical": numero(valore(temp, "CRITICAL")),
        })

    for psu in dati.findall("POWER_SUPPLIES/SUPPLY"):
        esito["psus"].append({
            "label": valore(psu, "LABEL"),
            "status": valore(psu, "STATUS"),
        })

    # I dischi sono elementi fratelli: <DRIVE BAY="1"/> apre la voce e
    # i successivi PRODUCT e DRIVE_STATUS le appartengono.
    for backplane in dati.findall("DRIVES/BACKPLANE"):
        corrente = None
        for nodo in backplane:
            if nodo.tag == "DRIVE":
                corrente = {"bay": (nodo.get("BAY") or "").strip(),
                            "enclosure": None, "product": None, "status": None}
                esito["drives"].append(corrente)
            elif corrente is not None and nodo.tag == "PRODUCT":
                corrente["product"] = (nodo.get("ID") or "").strip()
            elif corrente is not None and nodo.tag == "DRIVE_STATUS":
                corrente["status"] = (nodo.get("VALUE") or "").strip()

    glance = dati.find("HEALTH_AT_A_GLANCE")
    if glance is not None:
        for nodo in glance:
            for chiave, v in nodo.attrib.items():
                esito["glance"][f"{nodo.tag}.{chiave.strip()}"] = (v or "").strip()
    return esito


def salute_complessiva(glance):
    """Il peggiore degli stati in HEALTH_AT_A_GLANCE (ignora le ridondanze)."""
    peggiore = None
    ordine = {None: 0, "OK": 1, "Warning": 2, "Critical": 3}
    for chiave, v in glance.items():
        if not chiave.endswith(".STATUS"):
            continue
        h = salute(v)
        if ordine.get(h, 0) > ordine.get(peggiore, 0):
            peggiore = h
    return peggiore


def parse_potenza(dati):
    if dati is None:
        return {}
    return {
        "present": numero(valore(dati, "PRESENT_POWER_READING")),
        "average": numero(valore(dati, "AVERAGE_POWER_READING")),
        "maximum": numero(valore(dati, "MAXIMUM_POWER_READING")),
        "minimum": numero(valore(dati, "MINIMUM_POWER_READING")),
    }


def _stringhe_smbios(b64):
    """Testi di un record SMBIOS: seguono l'area formattata, separati da \0."""
    import base64
    try:
        dati = base64.b64decode(b64)
    except Exception:
        return b"", []
    if len(dati) < 2:
        return dati, []
    lunghezza = dati[1]
    testi = dati[lunghezza:].split(b"\x00")
    return dati, [t.decode("latin-1").strip() for t in testi]


def _smbios_testo(dati, testi, offset):
    if len(dati) <= offset:
        return None
    indice = dati[offset]
    if indice == 0 or indice > len(testi):
        return None
    return testi[indice - 1] or None


def parse_host_data(dati):
    """GET_HOST_DATA -> BIOS, sistema, processori, memoria, schede di rete."""
    esito = {"bios": None, "processors": [], "memory": [], "nics": [],
             "model": None, "serial_number": None, "uuid": None}
    if dati is None:
        return esito
    for rec in dati.findall("SMBIOS_RECORD"):
        tipo = rec.get("TYPE")
        campi = [(f.get("NAME"), (f.get("VALUE") or "").strip())
                 for f in rec.findall("FIELD")]
        diz = {}
        for nome, v in campi:
            diz.setdefault(nome, v)
        if tipo == "0":
            fam, data = diz.get("Family"), diz.get("Date")
            esito["bios"] = " ".join(x for x in (fam, data) if x) or None
        elif tipo == "1":
            esito["model"] = diz.get("Product Name")
            esito["serial_number"] = (diz.get("Serial Number") or "").strip() or None
            esito["uuid"] = diz.get("cUUID")
        elif tipo == "4":
            grezzi, testi = _stringhe_smbios(rec.get("B64_DATA") or "")
            tecnologia = diz.get("Execution Technology") or ""
            m_core = re.search(r"(\d+)\s+of\s+(\d+)\s+cores", tecnologia)
            m_thr = re.search(r"(\d+)\s+threads", tecnologia)
            esito["processors"].append({
                "label": diz.get("Label"),
                "model": _smbios_testo(grezzi, testi, 0x10),
                "manufacturer": _smbios_testo(grezzi, testi, 0x07),
                "speed_mhz": numero(diz.get("Speed")),
                "cores": int(m_core.group(1)) if m_core else None,
                "threads": int(m_thr.group(1)) if m_thr else None,
            })
        elif tipo == "17":
            dimensione = diz.get("Size") or ""
            if "not installed" in dimensione.lower():
                continue
            mb = numero(dimensione)
            esito["memory"].append({
                "label": diz.get("Label"),
                "size_mb": int(mb) if mb else None,
                "speed_mhz": numero(diz.get("Speed")),
            })
        elif tipo == "209":
            porta = None
            for nome, v in campi:
                if nome == "Port":
                    porta = v
                elif nome == "MAC" and porta and porta.lower() != "ilo":
                    esito["nics"].append({
                        "port": porta,
                        "mac": v.replace("-", ":").lower(),
                    })
    return esito


def parse_registro(dati):
    """EVENT_LOG -> lista di voci (sia registro iLO sia IML)."""
    voci = []
    if dati is None:
        return voci
    for ev in dati.findall("EVENT"):
        a = {k.strip(): (v or "").strip() for k, v in ev.attrib.items()}
        voci.append({
            "severity": a.get("SEVERITY"),
            "class": a.get("CLASS"),
            "last": a.get("LAST_UPDATE"),
            "initial": a.get("INITIAL_UPDATE"),
            "count": int(numero(a.get("COUNT")) or 1),
            "description": a.get("DESCRIPTION"),
        })
    return voci


def identita(rib):
    """Identita' del server per l'aggiunta dalla UI (come probe Redfish).

    Due accessi: /xmldata (senza credenziali) e un lotto con
    firmware, nome e stato di accensione, che verifica anche la password.
    """
    info = parse_xmldata(rib.xmldata())
    elementi, _ = rib.leggi([
        ("RIB_INFO", "read", ["<GET_FW_VERSION/>"]),
        ("SERVER_INFO", "read", ["<GET_SERVER_NAME/>",
                                  "<GET_HOST_POWER_STATUS/>"]),
    ])
    fw = trova(elementi, "GET_FW_VERSION")
    if fw is None:
        raise RibclError("l'iLO non ha restituito la versione del firmware")
    nome = trova(elementi, "SERVER_NAME")
    potenza = trova(elementi, "GET_HOST_POWER")
    processore = (fw.get("MANAGEMENT_PROCESSOR") or "").strip()
    m = re.search(r"(\d)", processore)
    generazione = f"iLO {m.group(1)}" if m else (processore or "iLO")
    stato = (potenza.get("HOST_POWER") or "").strip().upper() if potenza is not None else ""
    return {
        "hostname": (nome.get("VALUE") or "").strip() or None if nome is not None else None,
        "manufacturer": "HP",
        "model": info.get("model"),
        "serial_number": info.get("serial_number"),
        "uuid": info.get("uuid"),
        "bios_version": None,
        "ilo_version": generazione,
        "ilo_firmware": " ".join(x for x in (
            (fw.get("FIRMWARE_VERSION") or "").strip(),
            (fw.get("FIRMWARE_DATE") or "").strip()) if x) or None,
        "ilo_license": (fw.get("LICENSE_TYPE") or "").strip() or None,
        "overall_health": None,
        "state": "Enabled",
        "power_state": {"ON": "On", "OFF": "Off"}.get(stato),
        "processor_model": None,
        "processor_count": None,
        "memory_total_gib": None,
    }


def e_ilo_ribcl(host, timeout=20):
    """Vero se a quell'indirizzo risponde un iLO 2 o 3 (niente Redfish).

    Legge /xmldata, che non chiede credenziali: costa una connessione.
    """
    rib = Ribcl(host, "", "", timeout=timeout, timeout_tls=timeout)
    try:
        gen = generazione_da_xmldata(parse_xmldata(rib.xmldata()))
    except Exception:
        return False
    return gen in (2, 3)


# ------------------------------------------------------------------ prova


def oscura(testo):
    """Toglie la chiave di licenza dal file che verra' condiviso."""
    return re.sub(r'(LICENSE_KEY\s+VALUE=)"[^"]*"', r'\1"(nascosta)"', testo)

COMANDI_PROVA = [
    ("RIB_INFO", "read", "<GET_FW_VERSION/>"),
    ("SERVER_INFO", "read", "<GET_SERVER_NAME/>"),
    ("SERVER_INFO", "read", "<GET_HOST_POWER_STATUS/>"),
    ("SERVER_INFO", "read", "<GET_UID_STATUS/>"),
    ("SERVER_INFO", "read", "<GET_EMBEDDED_HEALTH/>"),
    ("SERVER_INFO", "read", "<GET_POWER_READINGS/>"),
    ("SERVER_INFO", "read", "<GET_HOST_DATA/>"),
    ("RIB_INFO", "read", "<GET_NETWORK_SETTINGS/>"),
    ("RIB_INFO", "read", "<GET_EVENT_LOG/>"),
    # Su iLO 2 e 3 l'IML si legge cosi': GET_IML esiste solo dal 4.
    ("SERVER_INFO", "read", "<GET_EVENT_LOG/>"),
]


def prova(host, utente, password, percorso):
    rib = Ribcl(host, utente, password)
    riepilogo = []
    with open(percorso, "w", encoding="utf-8") as fh:
        fh.write(f"# prova RIBCL - {host}\n")
        fh.write(f"# {datetime.now().isoformat(timespec='seconds')}\n\n")

        print(f"Connessione a {host}...")
        try:
            corpo = rib.xmldata()
            print(f"  TLS: {rib.ultima_tls}")
            fh.write("=" * 70 + "\n/xmldata?item=all\n" + "=" * 70 + "\n")
            fh.write(f"# TLS: {rib.ultima_tls}\n{corpo}\n\n")
            print("  letto /xmldata")
        except Exception as exc:
            fh.write(f"/xmldata NON DISPONIBILE: {type(exc).__name__}: {exc}\n\n")
            print(f"  /xmldata non disponibile: {type(exc).__name__}: {exc}")

        for sezione, modo, interno in COMANDI_PROVA:
            nome = interno.strip("</>")
            if nome == "GET_EVENT_LOG":
                nome = ("IML (SERVER_INFO/GET_EVENT_LOG)" if sezione == "SERVER_INFO"
                        else "registro iLO (RIB_INFO/GET_EVENT_LOG)")
            fh.write("=" * 70 + f"\n{nome}\n" + "=" * 70 + "\n")
            inizio = time.monotonic()
            gia_scelto = rib.protocollo is not None
            errore = None
            try:
                grezzo, dati = rib.comando(sezione, modo, interno)
                durata = time.monotonic() - inizio
                fh.write(f"# modo di invio: {rib.protocollo}, {durata:.1f}s, "
                         f"TLS: {rib.ultima_tls}\n")
                fh.write(oscura(grezzo) + "\n\n")
                esito = "ok" if dati is not None else "ok (nessun dato)"
            except Exception as exc:
                errore = exc
                durata = time.monotonic() - inizio
                fh.write(f"ERRORE dopo {durata:.1f}s: {type(exc).__name__}: {exc}\n\n")
                esito = f"errore: {exc}"

            if not gia_scelto and rib.tentativi:
                fh.write("# formati di invio provati:\n")
                for nome_modo, secondi, testo in rib.tentativi:
                    fh.write(f"## {nome_modo} ({secondi}s)\n{oscura(testo)[:3000]}\n")
                fh.write("\n")
                rib.tentativi = []

            if isinstance(errore, IloNonRisponde):
                print(f"  {nome}: {esito}")
                print("\nL'iLO non accetta piu' connessioni: probabilmente ha "
                      "ancora occupate\nquelle delle prove precedenti. Aspetta "
                      "qualche minuto, oppure riavvia\nl'iLO dalla sua pagina web "
                      "(Diagnostics > Reset iLO: il server non si\nspegne), "
                      "poi rilancia la prova.")
                break
            if rib.protocollo is None:
                # Nessun formato accettato al primo comando: provare gli
                # altri comandi non aggiunge nulla e affatica l'iLO.
                print(f"  {nome}: {esito}")
                print("\nNessun formato di invio accettato: il file contiene "
                      "le risposte\ndi ogni tentativo, mandamelo.")
                break
            riepilogo.append((nome, esito, durata))
            time.sleep(1)
            print(f"  {nome}: {esito} ({durata:.1f}s)")

    print(f"\nRisposte salvate in {percorso}")
    print("La password non e' scritta nel file.")
    return 0 if riepilogo and all(e.startswith("ok") for _, e, _ in riepilogo) else 1


def main():
    parser = argparse.ArgumentParser(description="Client RIBCL per iLO 2")
    parser.add_argument("--probe", metavar="IP", required=True,
                        help="interroga questo iLO e salva le risposte")
    parser.add_argument("--user", default="Administrator")
    args = parser.parse_args()

    password = getpass.getpass(f"Password iLO per {args.user}@{args.probe}: ")
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ip_file = re.sub(r"[^0-9A-Za-z.-]", "_", args.probe)
    percorso = os.path.join(LOG_DIR, f"ilo2-{ip_file}-{stamp}.txt")
    return prova(args.probe, args.user, password, percorso)


if __name__ == "__main__":
    sys.exit(main())
