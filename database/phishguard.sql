-- PhishGuard: Phishing URL Detection System
-- Database schema. Import via phpMyAdmin or: mysql -u root < database/phishguard.sql

CREATE DATABASE IF NOT EXISTS phishguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishguard;

-- Every URL a user scans, with the result
CREATE TABLE IF NOT EXISTS scans (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    url         TEXT NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    score       TINYINT UNSIGNED NOT NULL,          -- 0 (safe) to 100 (phishing)
    verdict     ENUM('safe', 'suspicious', 'phishing') NOT NULL,
    reasons     JSON NOT NULL,                      -- list of rules that were triggered
    ip_address  VARCHAR(45),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Domains known to be phishing
CREATE TABLE IF NOT EXISTS blacklist (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    note        VARCHAR(255),
    added_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Domains known to be legitimate (skip heavy penalties)
CREATE TABLE IF NOT EXISTS whitelist (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    added_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- URLs reported by users for admin review
--   phishing:       the user believes the link is phishing (confirmed reports feed the blacklist)
--   false_positive: the user believes a genuine site was flagged (confirmed reports feed the whitelist)
CREATE TABLE IF NOT EXISTS reports (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    url         TEXT NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    type        ENUM('phishing', 'false_positive') NOT NULL DEFAULT 'phishing',
    reason      VARCHAR(500),
    scan_id     INT NULL,
    ip_address  VARCHAR(45),
    status      ENUM('pending', 'confirmed', 'rejected') DEFAULT 'pending',
    reviewed_at TIMESTAMP NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reports_domain (domain),
    INDEX idx_reports_status (status),
    CONSTRAINT fk_reports_scan FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL
);

-- Admin accounts (password stored as a hash, never plain text)
CREATE TABLE IF NOT EXISTS admins (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Starter whitelist of well-known legitimate domains
INSERT IGNORE INTO whitelist (domain) VALUES
    ('google.com'), ('youtube.com'), ('facebook.com'), ('microsoft.com'),
    ('apple.com'), ('amazon.com'), ('paypal.com'), ('github.com'),
    ('wikipedia.org'), ('linkedin.com'), ('instagram.com'), ('x.com');
