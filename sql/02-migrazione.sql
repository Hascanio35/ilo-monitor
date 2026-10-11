-- ============================================================
-- iLO Monitor - migrazione schema v1 -> v2
-- Aggiunge il supporto multi-server (credenziali per server),
-- l'inventario CPU/memoria e la tabella impostazioni.
-- Eseguibile piu' volte senza effetti collaterali.
-- ============================================================



-- ------------------------------------------------------------
-- servers: credenziali e stato raccolta per singolo server
-- ------------------------------------------------------------

DROP PROCEDURE IF EXISTS add_column_if_missing;

DELIMITER //
CREATE PROCEDURE add_column_if_missing(
    IN tbl VARCHAR(64),
    IN col VARCHAR(64),
    IN ddl TEXT
)
BEGIN
    DECLARE found INT DEFAULT 0;

    SELECT COUNT(*) INTO found
      FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = tbl
       AND COLUMN_NAME = col;

    IF found = 0 THEN
        SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD COLUMN ', ddl);
        PREPARE st FROM @s;
        EXECUTE st;
        DEALLOCATE PREPARE st;
    END IF;
END //
DELIMITER ;

CALL add_column_if_missing('servers', 'ilo_user',
    '`ilo_user` VARCHAR(150) NOT NULL DEFAULT ''Administrator''');
CALL add_column_if_missing('servers', 'ilo_password_enc',
    '`ilo_password_enc` TEXT NULL');
CALL add_column_if_missing('servers', 'server_group',
    '`server_group` VARCHAR(100) NULL');
CALL add_column_if_missing('servers', 'notes',
    '`notes` TEXT NULL');
CALL add_column_if_missing('servers', 'last_collect_status',
    '`last_collect_status` VARCHAR(20) NULL');
CALL add_column_if_missing('servers', 'last_collect_at',
    '`last_collect_at` DATETIME NULL');
CALL add_column_if_missing('servers', 'last_error',
    '`last_error` TEXT NULL');
CALL add_column_if_missing('servers', 'power_state',
    '`power_state` VARCHAR(30) NULL');
CALL add_column_if_missing('servers', 'bios_version',
    '`bios_version` VARCHAR(100) NULL');
CALL add_column_if_missing('servers', 'uuid',
    '`uuid` VARCHAR(100) NULL');
CALL add_column_if_missing('servers', 'indicator_led',
    '`indicator_led` VARCHAR(30) NULL');
-- Ultima volta che si e' letto l'inventario (CPU, memoria, dischi,
-- rete, log): sono dati che cambiano di rado e costano molte
-- richieste, quindi si aggiornano meno spesso delle metriche.
-- Licenza iLO: la console remota HTML5 richiede iLO Advanced.
CALL add_column_if_missing('servers', 'ilo_license',
    '`ilo_license` VARCHAR(120) NULL');

CALL add_column_if_missing('servers', 'last_inventory_at',
    '`last_inventory_at` DATETIME NULL');

CALL add_column_if_missing('servers', 'last_boot_at',
    '`last_boot_at` DATETIME NULL');

-- Sessione Redfish riutilizzata tra una raccolta e l'altra: senza
-- questa ogni esecuzione apre e chiude una sessione, e l'iLO
-- registra due voci nel proprio log eventi (35.1017 / 35.1018)
-- riempiendolo di rumore a scapito degli eventi hardware.
CALL add_column_if_missing('servers', 'ilo_session_token',
    '`ilo_session_token` TEXT NULL');
CALL add_column_if_missing('servers', 'ilo_session_location',
    '`ilo_session_location` VARCHAR(500) NULL');
CALL add_column_if_missing('servers', 'ilo_session_at',
    '`ilo_session_at` DATETIME NULL');
CALL add_column_if_missing('servers', 'processor_summary',
    '`processor_summary` VARCHAR(255) NULL');
CALL add_column_if_missing('servers', 'processor_count',
    '`processor_count` INT NULL');
CALL add_column_if_missing('servers', 'core_count',
    '`core_count` INT NULL');
CALL add_column_if_missing('servers', 'memory_total_gib',
    '`memory_total_gib` DECIMAL(10,2) NULL');

CALL add_column_if_missing('ilo_events', 'log_source',
    '`log_source` VARCHAR(20) NOT NULL DEFAULT ''IEL''');

CALL add_column_if_missing('physical_drives', 'serial_number',
    '`serial_number` VARCHAR(100) NULL');
CALL add_column_if_missing('physical_drives', 'endurance_used_percent',
    '`endurance_used_percent` DECIMAL(8,2) NULL');
CALL add_column_if_missing('physical_drives', 'power_on_hours',
    '`power_on_hours` INT NULL');
CALL add_column_if_missing('servers', 'ams_status',
    '`ams_status` VARCHAR(30) NULL');
CALL add_column_if_missing('servers', 'host_os',
    '`host_os` VARCHAR(255) NULL');
-- NULL o 'redfish' per iLO 4/5/6, 'ribcl' per iLO 2 e 3.
CALL add_column_if_missing('servers', 'ilo_protocol',
    '`ilo_protocol` VARCHAR(10) NULL');
-- Dischi inviati dallo script per Windows (sorgente 'os'), con i
-- contatori SMART che l'iLO non conosce.
CALL add_column_if_missing('physical_drives', 'source',
    '`source` VARCHAR(10) NULL');
CALL add_column_if_missing('physical_drives', 'temperature_c',
    '`temperature_c` DECIMAL(6,1) NULL');
CALL add_column_if_missing('physical_drives', 'uncorrected_errors',
    '`uncorrected_errors` BIGINT NULL');
CALL add_column_if_missing('physical_drives', 'smart_json',
    '`smart_json` TEXT NULL');
CALL add_column_if_missing('servers', 'agent_token_hash',
    '`agent_token_hash` CHAR(64) NULL');
CALL add_column_if_missing('servers', 'agent_last_at',
    '`agent_last_at` DATETIME NULL');
CALL add_column_if_missing('servers', 'agent_host',
    '`agent_host` VARCHAR(255) NULL');

DROP PROCEDURE IF EXISTS add_column_if_missing;

-- La chiave unica deve includere la sorgente: IEL (log dell'iLO) e
-- IML (log hardware del sistema) numerano gli eventi per conto
-- proprio, quindi due voci diverse possono avere lo stesso numero.
DROP PROCEDURE IF EXISTS rebuild_event_key;

DELIMITER //
CREATE PROCEDURE rebuild_event_key()
BEGIN
    DECLARE found INT DEFAULT 0;

    SELECT COUNT(*) INTO found
      FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'ilo_events'
       AND INDEX_NAME = 'uq_server_event_source';

    IF found = 0 THEN
        SELECT COUNT(*) INTO found
          FROM information_schema.STATISTICS
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME = 'ilo_events'
           AND INDEX_NAME = 'uq_server_event';

        IF found > 0 THEN
            ALTER TABLE ilo_events DROP INDEX uq_server_event;
        END IF;

        ALTER TABLE ilo_events
            ADD UNIQUE KEY uq_server_event_source
                (server_id, log_source, event_number);
    END IF;
END //
DELIMITER ;

CALL rebuild_event_key();
DROP PROCEDURE IF EXISTS rebuild_event_key;

-- ------------------------------------------------------------
-- Inventario processori
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS processors (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    processor_id VARCHAR(100) NOT NULL,
    socket VARCHAR(100) NULL,
    model VARCHAR(255) NULL,
    manufacturer VARCHAR(100) NULL,
    max_speed_mhz INT NULL,
    total_cores INT NULL,
    total_threads INT NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    INDEX idx_cpu_server_date (server_id, collected_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Inventario moduli di memoria
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS memory_modules (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    dimm_id VARCHAR(100) NOT NULL,
    device_locator VARCHAR(150) NULL,
    capacity_mib INT NULL,
    speed_mhz INT NULL,
    memory_type VARCHAR(50) NULL,
    manufacturer VARCHAR(100) NULL,
    part_number VARCHAR(150) NULL,
    rank_count INT NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    INDEX idx_dimm_server_date (server_id, collected_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Utenti e sessioni dell'interfaccia
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS app_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS app_sessions (
    token CHAR(64) PRIMARY KEY,
    user_id INT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    client_ip VARCHAR(45) NULL,
    FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE,
    INDEX idx_sessions_expiry (expires_at)
) ENGINE=InnoDB;

-- Tentativi di accesso falliti, per rallentare gli attacchi a
-- forza bruta e per lasciarne traccia.
CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NULL,
    client_ip VARCHAR(45) NULL,
    attempted_at DATETIME NOT NULL,
    success TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_attempts (client_ip, attempted_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Avvisi via email
-- ------------------------------------------------------------

-- Una riga per server: cosa deve far partire un'email per quel
-- server. Viene creata con i valori predefiniti quando il server
-- entra in elenco.
CREATE TABLE IF NOT EXISTS server_alerts (
    server_id BIGINT UNSIGNED PRIMARY KEY,
    enabled TINYINT(1) NOT NULL DEFAULT 1,

    -- Gravita' minima degli eventi di log da segnalare.
    min_severity ENUM('Informational','Warning','Critical')
        NOT NULL DEFAULT 'Critical',

    -- Categorie di evento da seguire.
    cat_storage TINYINT(1) NOT NULL DEFAULT 1,
    cat_fans TINYINT(1) NOT NULL DEFAULT 1,
    cat_thermal TINYINT(1) NOT NULL DEFAULT 1,
    cat_power TINYINT(1) NOT NULL DEFAULT 1,
    cat_memory TINYINT(1) NOT NULL DEFAULT 1,
    cat_cpu TINYINT(1) NOT NULL DEFAULT 1,
    cat_network TINYINT(1) NOT NULL DEFAULT 0,
    cat_other TINYINT(1) NOT NULL DEFAULT 0,

    -- Avvisi che non nascono dal log ma dallo stato dei componenti.
    alert_temperature TINYINT(1) NOT NULL DEFAULT 1,
    alert_drives TINYINT(1) NOT NULL DEFAULT 1,
    alert_psu_fans TINYINT(1) NOT NULL DEFAULT 1,
    alert_unreachable TINYINT(1) NOT NULL DEFAULT 1,

    last_alert_at DATETIME NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Stato noto dei componenti, per accorgersi dei cambiamenti senza
-- rimandare la stessa email a ogni raccolta.
CREATE TABLE IF NOT EXISTS alert_state (
    server_id BIGINT UNSIGNED NOT NULL,
    kind VARCHAR(30) NOT NULL,
    item_key VARCHAR(150) NOT NULL,
    state VARCHAR(120) NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (server_id, kind, item_key),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Storico delle email inviate: utile per capire cosa e' partito e
-- per non ripetere lo stesso avviso.
CREATE TABLE IF NOT EXISTS alert_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NULL,
    sent_at DATETIME NOT NULL,
    subject VARCHAR(255) NULL,
    recipients VARCHAR(255) NULL,
    body MEDIUMTEXT NULL,
    status VARCHAR(20) NOT NULL,
    error_message TEXT NULL,
    INDEX idx_alert_log_date (sent_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Impostazioni applicative (chiave/valore)
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT INTO settings (setting_key, setting_value) VALUES
    ('temp_warning_c', '55'),
    ('temp_critical_c', '70'),
    ('collect_interval_minutes', '5'),
    ('ui_refresh_seconds', '45'),
    ('retention_days', '90'),
    ('ignore_login_events', '1'),
    ('inventory_interval_minutes', '60'),
    ('session_hours', '12'),
    ('smtp_enabled', '0'),
    ('smtp_host', ''),
    ('smtp_port', '587'),
    ('smtp_security', 'starttls'),
    ('smtp_user', ''),
    ('smtp_password_enc', ''),
    ('smtp_from', ''),
    ('smtp_to', ''),
    ('smtp_timeout', '20'),
    ('alert_max_per_run', '10')
ON DUPLICATE KEY UPDATE setting_key = setting_key;

-- ------------------------------------------------------------
-- Indici utili alle query della dashboard
-- ------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_events_created
    ON ilo_events (event_created);

-- ------------------------------------------------------------
-- Consumi a zero: sono "non misurato", non zero watt
-- ------------------------------------------------------------
-- I server con alimentatore non gestito (es. ML30 Gen9) riportano 0
-- invece di omettere il valore. Un server acceso non consuma zero
-- watt: lo zero falserebbe medie, totali e grafici. Idempotente.
UPDATE power_metrics SET consumed_watts = NULL WHERE consumed_watts = 0;
UPDATE power_metrics SET average_watts  = NULL WHERE average_watts  = 0;
UPDATE power_metrics SET maximum_watts  = NULL WHERE maximum_watts  = 0;
UPDATE power_metrics SET minimum_watts  = NULL WHERE minimum_watts  = 0;

-- ------------------------------------------------------------
-- Statistiche aggiornate per le tabelle che crescono di piu':
-- con stime vecchie MariaDB puo' scegliere piani lenti.
-- ------------------------------------------------------------
ANALYZE TABLE system_metrics, power_metrics, thermal_sensors, ilo_events;
