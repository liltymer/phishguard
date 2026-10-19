# PhishGuard — Phishing URL Detection System

A web application that analyses URLs for common phishing indicators and gives a
risk score with a verdict: **Safe**, **Suspicious** or **Phishing**.

## Tech stack

- HTML5, CSS3, Bootstrap 5
- JavaScript
- PHP 8
- MySQL

## Setup (XAMPP)

1. Clone this repository into `C:\xampp\htdocs\phishguard`.
2. Start **Apache** and **MySQL** in the XAMPP Control Panel.
3. Open phpMyAdmin (`http://localhost/phpmyadmin`) and import `database/phishguard.sql`.
4. Visit `http://localhost/phishguard`.

## Project structure

```
phishguard/
├── assets/
│   ├── css/style.css
│   └── js/main.js
├── config/db.php          Database connection
├── database/phishguard.sql
├── includes/
│   ├── Detector.php       Detection engine (all phishing rules)
│   ├── functions.php      Shared helpers (escaping, verdict labels, time ago)
│   ├── header.php
│   └── footer.php
├── tests/detector_test.php
├── index.php              Home page with URL scanner
├── scan.php               Runs the detector and saves the scan
├── result.php             Risk gauge, URL breakdown and reasons
└── history.php            Past scans with stats, search, filter and pages
```

## How detection works

Each rule that matches adds points to a risk score (capped at 100):

| Score | Verdict |
|-------|---------|
| 0–29 | Safe |
| 30–59 | Suspicious |
| 60–100 | Phishing |

| Check | Points |
|-------|--------|
| Domain on blacklist | 100 |
| Misspelt brand (e.g. `paypa1.com`) | 55 |
| IP address instead of a domain | 45 |
| Brand name on a domain it doesn't own | 35 |
| `@` symbol before the real host | 30 |
| Punycode (`xn--`) lookalike characters | 25 |
| Three or more subdomains | 20 |
| Link shortener | 20 |
| Trick words (login, verify, secure…) | up to 20, +10 if in the domain name |
| Risky TLD (`.tk`, `.xyz`, `.top`…) | 15 |
| Hyphens in the domain name | 5–15 |
| Very long URL | 8–15 |
| No HTTPS, unusual port, `//` redirect, heavy `%` encoding | 10 each |

Domains on the whitelist (e.g. `google.com`) are trusted and score 0.

Run the detector tests with:

```
C:\xampp\php\php.exe tests\detector_test.php
```

## Progress

- [x] Phase 1: Project setup, database, home page
- [x] Phase 2: Detection engine
- [x] Phase 3: Results page and scan history
- [ ] Phase 4: URL reporting, blacklist and whitelist
- [ ] Phase 5: Admin panel
- [ ] Phase 6: Testing and final polish
