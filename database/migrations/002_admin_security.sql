-- Phase 5 upgrade for databases created before the admin panel was added.
-- Fresh installs do not need this: database/phishguard.sql already includes these changes.
-- Run once via phpMyAdmin (SQL tab) or: mysql -u root < database/migrations/002_admin_security.sql

USE phishguard;

-- Failed admin logins, used to lock out password guessing
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    ip_address   VARCHAR(45) NOT NULL,
    username     VARCHAR(50),
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_attempts_ip_time (ip_address, attempted_at)
);

-- Let trusted-list entries carry a note, like blacklist entries
ALTER TABLE whitelist ADD COLUMN note VARCHAR(255) AFTER domain;

ALTER TABLE admins ADD COLUMN last_login_at TIMESTAMP NULL AFTER password_hash;
