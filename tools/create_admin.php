<?php
/**
 * Create an admin account, or reset the password of an existing one.
 * Command line only, so there is never a default password in the code.
 *
 *   C:\xampp\php\php.exe tools\create_admin.php <username> <password>
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/../config/db.php';

[, $username, $password] = $argv + [null, null, null];

if ($username === null || $password === null) {
    fwrite(STDERR, "Usage: php tools/create_admin.php <username> <password>\n");
    exit(1);
}

if (!preg_match('/^[A-Za-z0-9_]{3,50}$/', $username)) {
    fwrite(STDERR, "Username must be 3 to 50 characters: letters, numbers or underscores.\n");
    exit(1);
}

if (strlen($password) < 8) {
    fwrite(STDERR, "Password must be at least 8 characters.\n");
    exit(1);
}

// xmax = 0 is PostgreSQL's way of telling a fresh insert apart from an update
$stmt = db()->prepare(
    'INSERT INTO admins (username, password_hash) VALUES (?, ?)
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
     RETURNING (xmax = 0) AS inserted'
);
$stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
$inserted = in_array($stmt->fetchColumn(), [true, 't', 1, '1'], true);

echo $inserted ? "Admin \"$username\" created.\n" : "Password for \"$username\" updated.\n";
