<?php
// PostgreSQL connection. Settings live in config.local.php (see config.example.php).

// Any unexpected error on a web page: log the details for the developer, show visitors a friendly message
if (PHP_SAPI !== 'cli') {
    set_exception_handler(function (Throwable $e): void {
        error_log('PhishGuard error: ' . $e);
        if (!headers_sent()) {
            http_response_code(500);
        }
        echo '<div style="font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;text-align:center">'
            . '<h1 style="font-size:1.4rem">Something went wrong</h1>'
            . '<p style="color:#6c757d">Sorry, PhishGuard could not complete that request. Please try again in a moment.</p>'
            . '<p><a href="javascript:history.back()">Go back</a></p></div>';
    });
}

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
