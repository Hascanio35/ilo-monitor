# iLO Monitor

Pannello di monitoraggio centralizzato per server HPE ProLiant, basato
su Redfish. Raccoglie stato di salute, temperature, ventole, consumi,
storage, rete e log eventi da più iLO, li conserva in un database e li
mostra in un'unica interfaccia web, con avvisi via email.

Nato per non dover aprire sette interfacce iLO diverse per sapere come
stanno sette server.

> Progetto indipendente, non affiliato né approvato da Hewlett Packard
> Enterprise. "HPE", "ProLiant" e "iLO" sono marchi dei rispettivi
> titolari.

## Cosa fa

- **Multi-server.** Ogni iLO ha le sue credenziali, cifrate nel
  database. Un server che non risponde non blocca gli altri.
- **iLO 4, 5 e 6.** Le differenze fra generazioni sono gestite:
  chiave OEM `Hp` o `Hpe`, collezioni `Items` o `Members`, storage
  sotto `Storage` o sotto `SmartStorage`, paginazione dei log.
- **Inventario e stato.** Processori, moduli di memoria, dischi
  fisici e volumi, controller, interfacce di rete, alimentatori,
  sensori termici, ventole, consumi.
- **Eventi.** Importa IEL, IML, SL e Alert Event Log, deduplicati,
  con filtro per server, gravità, sorgente e testo. Gli accessi
  generati dal monitoraggio stesso si possono escludere.
- **Avvisi email.** Per ogni server si sceglie la gravità minima e
  quali categorie seguire, più quattro controlli sullo stato dei
  componenti che avvisano al cambiamento anziché a ripetizione.
- **Azioni.** Accensione, spegnimento ordinato o forzato, riavvio,
  LED di identificazione, apertura della console remota HTML5.
- **Telefono.** Sotto gli 820 pixel l'impaginazione cambia
  impostazione: barra di navigazione in basso, elenco a schede,
  menu che salgono dal basso. Si può aggiungere alla schermata home.

## Avvio rapido con Docker

```bash
git clone https://github.com/Hascanio35/ilo-monitor.git
cd ilo-monitor
cp .env.example .env
$EDITOR .env          # cambia almeno DB_PASSWORD e DB_ROOT_PASSWORD
docker compose up -d
```

L'interfaccia risponde su <http://localhost:8080>.

La password del primo accesso viene generata e stampata una sola
volta nei log:

```bash
docker compose logs api | grep -A6 "UTENZA CREATA"
```

In alternativa impostala tu in `.env` con `ADMIN_PASSWORD`.

### Servizi

| Servizio | Ruolo |
|---|---|
| `db` | MariaDB, dati su volume `db-data` |
| `api` | Interfaccia e API, applica lo schema all'avvio |
| `collector` | Interroga gli iLO a intervalli regolari |

`api` e `collector` condividono il volume `config`, che contiene
`secret.key`: **è la chiave che cifra le password degli iLO.**
Perderla significa doverle reinserire tutte. Vale la pena metterla nei
backup.

### Comandi utili

```bash
# raccolta immediata, senza aspettare il ciclo
docker compose exec collector python3 -m app.redfish_collector --full

# elenco dei server configurati e ultimo esito
docker compose exec collector python3 -m app.redfish_collector --list

# diagnostica di un iLO che non risponde come previsto
docker compose exec collector python3 -m app.redfish_collector --dump 3

# gestione degli utenti dell'interfaccia
docker compose exec api ilo-monitor-user list
docker compose exec api ilo-monitor-user add tecnico

# backup del database
docker compose exec db mariadb-dump -u root -p"$DB_ROOT_PASSWORD" \
  ilomonitor > backup.sql
```

## Installazione senza Docker

Per chi preferisce il servizio di sistema, in `install/` ci sono gli
script per Debian e Ubuntu, e in `systemd/` le unità. L'applicazione
va in `/opt/ilo-monitor`, con nginx davanti a uvicorn.

```bash
sudo ./install/upgrade.sh    # prima installazione o passaggio dalla v1
sudo ./install/update.sh     # aggiornamenti successivi
```

## Configurazione

Tutto si imposta dall'interfaccia, in Impostazioni e Avvisi email:
soglie di temperatura, frequenza di rilettura di inventario e log,
conservazione dello storico, server SMTP e regole di avviso.

Le variabili d'ambiente servono solo all'avvio e sono documentate in
[`.env.example`](.env.example).

## Utenza iLO consigliata

Per il solo monitoraggio basta un account con privilegio di lettura.
Per le azioni di alimentazione e il LED servono *Virtual Power and
Reset* e *Configure iLO Settings*. Conviene creare un utente dedicato
su ogni iLO invece di usare Administrator: la revoca è immediata se
serve.

## Sicurezza

L'interfaccia richiede autenticazione; le password sono salvate come
hash pbkdf2 con salt, e i tentativi falliti vengono limitati per
indirizzo.

Le password degli iLO sono cifrate nel database, ma la chiave sta
sulla stessa macchina: chi ha accesso amministrativo all'host può
leggerle. Vale la pena trattare l'installazione come un sistema con
credenziali privilegiate.

Il servizio parla HTTP. Su una rete di gestione o dietro VPN è
accettabile; esposto altrove, mettici davanti un reverse proxy con
TLS.

## Requisiti

- Docker con Compose, oppure Python 3.11+, MariaDB 10.6+ e nginx
- iLO raggiungibile via HTTPS dalla macchina che esegue il collector
- Licenza iLO Advanced per la console remota (il monitoraggio
  funziona anche senza)

## Licenza

MIT — vedi [LICENSE](LICENSE).
