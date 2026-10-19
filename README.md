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
├── includes/              Shared header and footer
└── index.php              Home page with URL scanner
```

## Progress

- [x] Phase 1: Project setup, database, home page
- [ ] Phase 2: Detection engine
- [ ] Phase 3: Results page and scan history
- [ ] Phase 4: URL reporting, blacklist and whitelist
- [ ] Phase 5: Admin panel
- [ ] Phase 6: Testing and final polish
