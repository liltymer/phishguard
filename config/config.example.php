<?php
/**
 * Database settings template.
 *
 * Copy this file to config.local.php in the same folder and fill in your own
 * PostgreSQL password. config.local.php is ignored by git, so your password
 * is never uploaded to GitHub.
 */
return [
    'host'     => 'localhost',
    'port'     => 5432,
    'database' => 'phishguard',
    'username' => 'postgres',
    'password' => 'YOUR_POSTGRES_PASSWORD',
];
