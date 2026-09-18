"""Cifratura delle password iLO salvate nel database.

La chiave vive in /opt/ilo-monitor/config/secret.key (0600, proprietario
root). Viene generata al primo avvio se assente. Se la chiave viene persa
le password salvate diventano illeggibili e vanno reinserite dalla UI.
"""

import os
import stat

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.getenv("ILO_MONITOR_BASE", "/opt/ilo-monitor")
KEY_PATH = os.path.join(BASE_DIR, "config", "secret.key")


def _load_key() -> bytes:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as fh:
            key = fh.read().strip()
        if key:
            return key

    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as fh:
        fh.write(key)
    os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return key


_fernet = Fernet(_load_key())


def encrypt(plaintext: str) -> str:
    """Cifra una password. Restituisce testo ASCII da salvare in colonna TEXT."""
    if plaintext is None:
        return None
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Decifra una password salvata. Solleva ValueError se la chiave non combacia."""
    if not ciphertext:
        return None
    try:
        return _fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Password iLO non decifrabile: la chiave in config/secret.key "
            "non corrisponde. Reinserire la password dalla interfaccia."
        ) from exc
