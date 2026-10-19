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

$stmt = db()->prepare(
    'INSERT INTO admins (username, password_hash) VALUES (?, ?)
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)'
);
$stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);

// MySQL reports 1 row affected for an insert and 2 for an update
echo $stmt->rowCount() === 1 ? "Admin \"$username\" created.\n" : "Password for \"$username\" updated.\n";
