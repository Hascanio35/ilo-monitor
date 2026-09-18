"""Autenticazione dell'interfaccia: hash delle password e sessioni.

Si appoggia solo alla libreria standard (hashlib, hmac, secrets) per
non aggiungere dipendenze: pbkdf2-hmac-sha256 con salt casuale per
utente e confronto a tempo costante.
"""

import hashlib
import hmac
import secrets

# Costo del calcolo dell'hash. Alzarlo rende piu' lento un attacco a
# forza bruta sul database, a spese di qualche decimo di secondo al
# login. Il valore usato viene salvato insieme all'hash, cosi' si puo'
# alzare in futuro senza invalidare le password esistenti.
ITERATIONS = 240_000
ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    """Restituisce una stringa 'algoritmo$iterazioni$salt$hash'."""
    if not password:
        raise ValueError("La password non puo' essere vuota")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("ascii"), iterations
    )
    return f"{ALGORITHM}${iterations}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Confronto a tempo costante fra password inserita e hash salvato."""
    if not password or not stored:
        return False
    try:
        algorithm, iterations, salt, expected = stored.split("$", 3)
    except ValueError:
        return False
    if algorithm != ALGORITHM:
        return False
    try:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("ascii"),
            int(iterations),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), expected)


def new_session_token() -> str:
    """Token di sessione: 32 byte casuali, non indovinabili."""
    return secrets.token_urlsafe(32)


# Le regole di composizione da sole non bastano: "Password12" le
# supera tutte ed e' fra le prime che si provano. Blocchiamo anche le
# radici piu' abusate e il nome utente stesso.
RADICI_COMUNI = (
    "password", "passw0rd", "qwerty", "123456", "abcdef", "admin",
    "iloveyou", "letmein", "welcome", "monkey", "dragon", "azerty",
    "ilomonitor", "hpe", "proliant", "changeme", "segreta", "password1",
)


def check_password_strength(password: str, username: str = None) -> str:
    """Restituisce un messaggio se la password e' troppo debole, altrimenti None."""
    if len(password or "") < 10:
        return "La password deve essere lunga almeno 10 caratteri."

    categorie = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if categorie < 3:
        return (
            "Usa almeno tre fra: minuscole, maiuscole, cifre e simboli."
        )

    minuscola = password.lower()

    # "Adm1n" e "P4ssw0rd" sono le stesse scelte ovvie scritte con le
    # cifre al posto delle lettere: le riportiamo alla forma normale
    # prima di confrontarle, altrimenti la lista non serve a niente.
    SOSTITUZIONI = str.maketrans(
        {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
         "@": "a", "$": "s", "!": "i", "|": "l"}
    )
    normalizzata = minuscola.translate(SOSTITUZIONI)

    for radice in RADICI_COMUNI:
        radice_normalizzata = radice.translate(SOSTITUZIONI)
        if radice in minuscola or radice_normalizzata in normalizzata:
            return (
                f"La password assomiglia troppo a \"{radice}\", fra le "
                f"prime combinazioni provate in un attacco. Scegline un'altra."
            )

    if username and len(username) >= 3 and username.lower() in minuscola:
        return "La password non puo' contenere il nome utente."

    if len(set(password)) < 5:
        return "La password usa troppi caratteri ripetuti."

    return None
