


CREATE TABLE IF NOT EXISTS servers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    hostname VARCHAR(255) NULL,
    ilo_ip VARCHAR(45) NOT NULL,
    ilo_version VARCHAR(50) NULL,
    ilo_firmware VARCHAR(100) NULL,
    manufacturer VARCHAR(100) NULL,
    model VARCHAR(255) NULL,
    serial_number VARCHAR(255) NULL,
    overall_health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_servers_ilo_ip (ilo_ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS collection_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    status ENUM('RUNNING','OK','ERROR') NOT NULL DEFAULT 'RUNNING',
    error_message TEXT NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_collection_server_date (server_id, started_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS system_metrics (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    cpu_utilization DECIMAL(8,2) NULL,
    cpu_power_watts DECIMAL(10,2) NULL,
    memory_utilization DECIMAL(8,2) NULL,
    memory_power_watts DECIMAL(10,2) NULL,
    io_bus_utilization DECIMAL(8,2) NULL,
    memory_bus_utilization DECIMAL(8,2) NULL,
    ambient_temperature DECIMAL(8,2) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_system_metrics_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS thermal_sensors (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    sensor_name VARCHAR(255) NOT NULL,
    sensor_number VARCHAR(100) NULL,
    temperature_c DECIMAL(8,2) NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    warning_threshold DECIMAL(8,2) NULL,
    critical_threshold DECIMAL(8,2) NULL,
    fatal_threshold DECIMAL(8,2) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_thermal_server_date
        (server_id, collected_at),
    INDEX idx_thermal_sensor
        (server_id, sensor_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fans (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    fan_id VARCHAR(100) NOT NULL,
    fan_name VARCHAR(255) NULL,
    status VARCHAR(50) NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    speed_percent DECIMAL(8,2) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_fans_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS power_supplies (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    psu_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NULL,
    capacity_watts DECIMAL(10,2) NULL,
    power_input_watts DECIMAL(10,2) NULL,
    power_output_watts DECIMAL(10,2) NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_psu_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS power_metrics (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    consumed_watts DECIMAL(10,2) NULL,
    average_watts DECIMAL(10,2) NULL,
    maximum_watts DECIMAL(10,2) NULL,
    minimum_watts DECIMAL(10,2) NULL,
    cpu_watts DECIMAL(10,2) NULL,
    dimm_watts DECIMAL(10,2) NULL,
    gpu_watts DECIMAL(10,2) NULL,
    power_capacity_watts DECIMAL(10,2) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_power_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS storage_controllers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    controller_id VARCHAR(100) NOT NULL,
    manufacturer VARCHAR(100) NULL,
    model VARCHAR(255) NULL,
    firmware VARCHAR(100) NULL,
    cache_mib DECIMAL(12,2) NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_storage_controller_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS physical_drives (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    drive_id VARCHAR(100) NOT NULL,
    bay VARCHAR(100) NULL,
    manufacturer VARCHAR(100) NULL,
    model VARCHAR(255) NULL,
    revision VARCHAR(100) NULL,
    protocol VARCHAR(50) NULL,
    media_type VARCHAR(50) NULL,
    capacity_bytes BIGINT UNSIGNED NULL,
    rotation_rpm DECIMAL(12,2) NULL,
    negotiated_speed_gbs DECIMAL(8,2) NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    failure_predicted BOOLEAN NULL,
    media_life_left_percent DECIMAL(8,2) NULL,
    serial_number VARCHAR(100) NULL,
    endurance_used_percent DECIMAL(8,2) NULL,
    power_on_hours INT NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_drives_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS storage_volumes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    volume_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NULL,
    raid_type VARCHAR(50) NULL,
    capacity_bytes BIGINT UNSIGNED NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_volumes_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS network_interfaces (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    interface_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NULL,
    mac_address VARCHAR(50) NULL,
    ipv4_address VARCHAR(100) NULL,
    link_status VARCHAR(50) NULL,
    interface_enabled BOOLEAN NULL,
    speed_mbps DECIMAL(12,2) NULL,
    health VARCHAR(50) NULL,
    state VARCHAR(50) NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_network_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ilo_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    event_number BIGINT NULL,
    event_created DATETIME NULL,
    severity VARCHAR(50) NULL,
    message_id VARCHAR(255) NULL,
    message TEXT NULL,
    raw_json JSON NULL,
    UNIQUE KEY uq_server_event (server_id, event_number),
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_events_server_date
        (server_id, event_created),
    INDEX idx_events_severity
        (server_id, severity)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS raw_snapshots (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id BIGINT UNSIGNED NOT NULL,
    collected_at DATETIME NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    payload JSON NOT NULL,
    FOREIGN KEY (server_id)
        REFERENCES servers(id)
        ON DELETE CASCADE,
    INDEX idx_raw_server_date
        (server_id, collected_at)
) ENGINE=InnoDB;

