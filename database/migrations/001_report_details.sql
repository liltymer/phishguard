-- Phase 4 upgrade for databases created before URL reporting was added.
-- Fresh installs do not need this: database/phishguard.sql already includes these columns.
-- Run once via phpMyAdmin (SQL tab) or: mysql -u root < database/migrations/001_report_details.sql

USE phishguard;

ALTER TABLE reports
    ADD COLUMN domain      VARCHAR(255) NOT NULL DEFAULT '' AFTER url,
    ADD COLUMN type        ENUM('phishing', 'false_positive') NOT NULL DEFAULT 'phishing' AFTER domain,
    ADD COLUMN scan_id     INT NULL AFTER reason,
    ADD COLUMN ip_address  VARCHAR(45) AFTER scan_id,
    ADD COLUMN reviewed_at TIMESTAMP NULL AFTER status,
    ADD INDEX idx_reports_domain (domain),
    ADD INDEX idx_reports_status (status),
    ADD CONSTRAINT fk_reports_scan FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL;

ALTER TABLE reports ALTER COLUMN domain DROP DEFAULT;
