<?php
// PostgreSQL connection. Settings live in config.local.php (see config.example.php).

function db(): PDO
{
    static $pdo = null;

    if ($pdo !== null) {
        return $pdo;
    }

    $configFile = __DIR__ . '/config.local.php';
    if (!is_file($configFile)) {
        http_response_code(500);
        exit('Database settings not found. Copy config/config.example.php to config/config.local.php and add your PostgreSQL password.');
    }

    $config = require $configFile;

    try {
        $pdo = new PDO(
            sprintf('pgsql:host=%s;port=%d;dbname=%s', $config['host'], $config['port'], $config['database']),
            $config['username'],
            $config['password'],
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]
        );
    } catch (PDOException $e) {
        http_response_code(500);
        exit('Database connection failed. Make sure PostgreSQL is running and the settings in config/config.local.php are correct.');
    }

    return $pdo;
}
