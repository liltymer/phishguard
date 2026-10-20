<?php
// Admin authentication: login, lockout after repeated failures, session timeout

const MAX_LOGIN_FAILURES = 5;
const LOCKOUT_MINUTES = 15;
const SESSION_TIMEOUT_SECONDS = 1800;

function isLockedOut(string $ip): bool
{
    $stmt = db()->prepare(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at > now() - INTERVAL '" . LOCKOUT_MINUTES . " minutes'"
    );
    $stmt->execute([$ip]);

    return $stmt->fetchColumn() >= MAX_LOGIN_FAILURES;
}

function attemptLogin(string $username, string $password, string $ip): bool
{
    $pdo = db();
    $stmt = $pdo->prepare('SELECT id, username, password_hash FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    $admin = $stmt->fetch();

    // Verify against a dummy hash when the user does not exist, so both cases take the same time
    $hash = $admin['password_hash'] ?? password_hash('no-such-user', PASSWORD_DEFAULT);
    $valid = password_verify($password, $hash) && $admin !== false;

    if (!$valid) {
        $pdo->prepare('INSERT INTO login_attempts (ip_address, username) VALUES (?, ?)')
            ->execute([$ip, mb_substr($username, 0, 50)]);
        return false;
    }

    if (password_needs_rehash($admin['password_hash'], PASSWORD_DEFAULT)) {
        $pdo->prepare('UPDATE admins SET password_hash = ? WHERE id = ?')
            ->execute([password_hash($password, PASSWORD_DEFAULT), $admin['id']]);
    }

    $pdo->prepare('DELETE FROM login_attempts WHERE ip_address = ?')->execute([$ip]);
    $pdo->prepare('UPDATE admins SET last_login_at = now() WHERE id = ?')->execute([$admin['id']]);

    // New session ID on login prevents session fixation attacks
    startSession();
    session_regenerate_id(true);
    $_SESSION['admin_id'] = (int) $admin['id'];
    $_SESSION['admin_username'] = $admin['username'];
    $_SESSION['last_activity'] = time();

    return true;
}

function logout(): void
{
    startSession();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }

    session_destroy();
}

function isLoggedIn(): bool
{
    startSession();

    if (empty($_SESSION['admin_id'])) {
        return false;
    }

    if (time() - ($_SESSION['last_activity'] ?? 0) > SESSION_TIMEOUT_SECONDS) {
        logout();
        return false;
    }

    $_SESSION['last_activity'] = time();
    return true;
}

// Put at the top of every admin page
function requireAdmin(): void
{
    if (!isLoggedIn()) {
        $page = basename($_SERVER['SCRIPT_NAME']);
        header('Location: login.php?next=' . urlencode($page));
        exit;
    }
}
