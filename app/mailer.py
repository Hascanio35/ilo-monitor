"""Invio delle email di avviso via SMTP autenticato."""

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

try:
    from app.crypto_util import decrypt
except ImportError:  # esecuzione diretta dalla cartella app/
    from crypto_util import decrypt


class MailError(Exception):
    """Errore di configurazione o di consegna, con messaggio leggibile."""


def smtp_config(settings):
    """Estrae e valida la configurazione SMTP dalle impostazioni."""
    host = (settings.get("smtp_host") or "").strip()
    if not host:
        raise MailError("Server SMTP non configurato")

    destinatari = [
        x.strip()
        for x in (settings.get("smtp_to") or "").replace(";", ",").split(",")
        if x.strip()
    ]
    if not destinatari:
        raise MailError("Nessun destinatario configurato")

    mittente = (settings.get("smtp_from") or "").strip()
    if not mittente:
        mittente = settings.get("smtp_user") or f"ilo-monitor@{host}"

    password = None
    cifrata = settings.get("smtp_password_enc")
    if cifrata:
        try:
            password = decrypt(cifrata)
        except Exception as exc:
            raise MailError(
                f"Password SMTP non decifrabile: {exc}"
            ) from exc

    try:
        porta = int(settings.get("smtp_port") or 587)
    except (TypeError, ValueError):
        porta = 587

    try:
        timeout = int(settings.get("smtp_timeout") or 20)
    except (TypeError, ValueError):
        timeout = 20

    return {
        "host": host,
        "port": porta,
        "security": (settings.get("smtp_security") or "starttls").lower(),
        "user": (settings.get("smtp_user") or "").strip() or None,
        "password": password,
        "from": mittente,
        "to": destinatari,
        "timeout": timeout,
    }


def send_mail(settings, subject, body, html=None):
    """Invia un messaggio. Solleva MailError con un messaggio leggibile."""
    cfg = smtp_config(settings)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["from"]
    message["To"] = ", ".join(cfg["to"])
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="ilo-monitor")
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")

    contesto = ssl.create_default_context()

    try:
        if cfg["security"] == "ssl":
            server = smtplib.SMTP_SSL(
                cfg["host"], cfg["port"], timeout=cfg["timeout"],
                context=contesto,
            )
        else:
            server = smtplib.SMTP(
                cfg["host"], cfg["port"], timeout=cfg["timeout"]
            )

        with server:
            server.ehlo()
            if cfg["security"] == "starttls":
                server.starttls(context=contesto)
                server.ehlo()
            if cfg["user"] and cfg["password"]:
                server.login(cfg["user"], cfg["password"])
            server.send_message(message)

    except smtplib.SMTPAuthenticationError as exc:
        raise MailError(
            f"Autenticazione SMTP rifiutata: {exc.smtp_error.decode(errors='replace') if isinstance(exc.smtp_error, bytes) else exc}"
        ) from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise MailError(f"Destinatario rifiutato: {exc.recipients}") from exc
    except smtplib.SMTPException as exc:
        raise MailError(f"Errore SMTP: {exc}") from exc
    except ssl.SSLError as exc:
        raise MailError(
            f"Errore TLS: {exc}. Verifica la modalita' di cifratura "
            f"(STARTTLS di solito sulla 587, SSL diretto sulla 465)."
        ) from exc
    except OSError as exc:
        raise MailError(
            f"Server SMTP non raggiungibile ({cfg['host']}:{cfg['port']}): {exc}"
        ) from exc

    return cfg["to"]
