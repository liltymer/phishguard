-- PhishGuard: Phishing URL Detection System
-- PostgreSQL schema.
--
-- 1. In pgAdmin, create an empty database named "phishguard".
-- 2. Right-click it > Query Tool > Open File > choose this file > Execute (F5).
-- Running it again is safe: existing tables and data are kept.

-- Every URL a user scans, with the result
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    url         TEXT NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    score       SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
    verdict     VARCHAR(10) NOT NULL CHECK (verdict IN ('safe', 'suspicious', 'phishing')),
    reasons     JSONB NOT NULL DEFAULT '[]',
    ip_address  VARCHAR(45),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans (verdict);
COMMENT ON TABLE scans IS 'Every URL scanned, with its risk score (0 to 100), verdict and the rules that were triggered';

-- Domains known to be phishing
CREATE TABLE IF NOT EXISTS blacklist (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    note        VARCHAR(255),
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE blacklist IS 'Known phishing domains: any URL on these scores 100';

-- Domains known to be legitimate
CREATE TABLE IF NOT EXISTS whitelist (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    note        VARCHAR(255),
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE whitelist IS 'Trusted domains: any URL on these scores 0';

-- URLs reported by users for admin review
--   phishing:       the user believes the link is phishing (confirmed reports feed the blacklist)
--   false_positive: the user believes a genuine site was flagged (confirmed reports feed the whitelist)
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    url         TEXT NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    type        VARCHAR(20) NOT NULL DEFAULT 'phishing' CHECK (type IN ('phishing', 'false_positive')),
    reason      VARCHAR(500),
    scan_id     INTEGER REFERENCES scans (id) ON DELETE SET NULL,
    ip_address  VARCHAR(45),
    status      VARCHAR(10) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'rejected')),
    reviewed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports (domain);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports (status);
COMMENT ON TABLE reports IS 'User reports of missed phishing links or false alarms, reviewed by an admin';

-- Admin accounts (password stored as a bcrypt hash, never plain text)
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE admins IS 'Administrator accounts';

-- Failed admin logins, used to lock out password guessing
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip_address   VARCHAR(45) NOT NULL,
    username     VARCHAR(50),
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts (ip_address, attempted_at);
COMMENT ON TABLE login_attempts IS 'Failed admin login attempts, used for the 15 minute lockout';

-- Starter list of well-known legitimate domains
INSERT INTO whitelist (domain) VALUES
    ('google.com'), ('youtube.com'), ('facebook.com'), ('microsoft.com'),
    ('apple.com'), ('amazon.com'), ('paypal.com'), ('github.com'),
    ('wikipedia.org'), ('linkedin.com'), ('instagram.com'), ('x.com')
ON CONFLICT (domain) DO NOTHING;
