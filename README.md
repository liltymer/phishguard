# PhishGuard: Phishing URL Detection System

A web application that analyses URLs for common phishing indicators and gives a
risk score with a verdict: **Safe**, **Suspicious** or **Phishing**.

## Tech stack

- HTML5, CSS3, Bootstrap 5
- JavaScript
- PHP 8 (served by Apache from XAMPP)
- PostgreSQL, managed with pgAdmin 4

## Setup

You need XAMPP (for Apache and PHP) and PostgreSQL with pgAdmin 4.

1. **Get the code.** Clone this repository into `C:\xampp\htdocs\phishguard`.
2. **Enable PostgreSQL in PHP.** Open `C:\xampp\php\php.ini`, find these two lines and remove the
   `;` at the start of each, then restart Apache in the XAMPP Control Panel:
   ```
   extension=pdo_pgsql
   extension=pgsql
   ```
3. **Create the database.** In pgAdmin, right-click **Databases > Create > Database**, name it
   `phishguard` and save. Then right-click the new database > **Query Tool**, open
   `database/phishguard.sql` and press **Execute (F5)**.
4. **Add your password.** Copy `config/config.example.php` to `config/config.local.php` and put your
   PostgreSQL password in it. This file is ignored by git, so it is never uploaded.
5. **Open the site** at `http://localhost/phishguard`.

### Creating an admin account

There is no default admin password. The first time you open `http://localhost/phishguard/admin`
(also linked in the site footer), a setup page asks you to create the first admin account. It only
works from the computer running the site, and disappears once an admin exists.

To add another admin or reset a password, use the command line:

```
C:\xampp\php\php.exe tools\create_admin.php <username> <password>
```

## Project structure

```
phishguard/
├── admin/
│   ├── setup.php          First-run admin account creation
│   ├── login.php          Admin login with lockout
│   ├── index.php          Dashboard: statistics and 7-day chart
│   ├── reports.php        Review user reports (confirm or reject)
│   ├── lists.php          Manage the blacklist and trusted list
│   ├── account.php        Change password
│   └── logout.php
├── assets/
│   ├── css/style.css
│   └── js/main.js
├── config/
│   ├── db.php             PostgreSQL connection
│   ├── config.example.php Settings template (committed)
│   └── config.local.php   Your password (not committed)
├── database/phishguard.sql PostgreSQL schema
├── includes/
│   ├── Detector.php       Detection engine (all phishing rules)
│   ├── auth.php           Admin login, lockout and session timeout
│   ├── functions.php      Shared helpers (escaping, CSRF, flash messages)
│   ├── header.php, footer.php, admin_header.php
├── tests/detector_test.php
├── tools/create_admin.php Command-line admin account tool
├── index.php              Home page with URL scanner
├── scan.php               Runs the detector and saves the scan
├── result.php             Risk gauge, URL breakdown and reasons
├── history.php            Past scans with stats, search, filter and pages
└── report.php             Users report missed phishing links or false alarms
```

## Security measures

- All database queries use prepared statements (protection against SQL injection).
- All output is escaped with `htmlspecialchars` (protection against XSS).
- Forms that change data carry a CSRF token.
- The report form has a hidden spam trap field and a limit of 5 reports per hour per IP address.
- Duplicate pending reports for the same URL are not stored twice.
- Admin passwords are stored with `password_hash` (bcrypt), never in plain text.
- Admin login locks for 15 minutes after 5 failed attempts and gives the same message for
  unknown users and wrong passwords.
- The session ID is regenerated on login, and admins are logged out after 30 minutes of inactivity.
- Logout requires a POST request with a CSRF token.
- The `config`, `includes`, `database`, `tests` and `tools` folders are blocked from browser access
  with `.htaccess`.

## Admin workflow

1. Users report a URL as phishing or as a false alarm.
2. The admin reviews it under **Reports** and chooses to apply the decision to the exact host
   (for example `login.evil.xyz`) or the whole domain (`evil.xyz` and all its subdomains).
3. Confirming a phishing report adds the domain to the **blacklist**; confirming a false alarm adds it
   to the **trusted list**. The domain is removed from the opposite list, and all other pending reports
   for that domain are closed.
4. Rejecting a report changes no lists.

## How detection works

Each rule that matches adds points to a risk score (capped at 100):

| Score | Verdict |
|-------|---------|
| 0 to 29 | Safe |
| 30 to 59 | Suspicious |
| 60 to 100 | Phishing |

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
| Hyphens in the domain name | 5 to 15 |
| Very long URL | 8 to 15 |
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
- [x] Phase 4: URL reporting, blacklist and whitelist
- [x] Phase 5: Admin panel
- [ ] Phase 6: Testing and final polish
