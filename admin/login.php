<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

// Only allow redirects to pages inside admin/, never to another website
$next = $_GET['next'] ?? $_POST['next'] ?? 'index.php';
if (!preg_match('/^[a-z_]+\.php$/', $next)) {
    $next = 'index.php';
}

if (isLoggedIn()) {
    header('Location: ' . $next);
    exit;
}

$error = '';
$username = '';
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        $error = 'Your session expired. Please try again.';
    } elseif (isLockedOut($ip)) {
        $error = 'Too many failed attempts. Please wait ' . LOCKOUT_MINUTES . ' minutes before trying again.';
    } elseif ($username === '' || $password === '') {
        $error = 'Please enter your username and password.';
    } elseif (attemptLogin($username, $password, $ip)) {
        header('Location: ' . $next);
        exit;
    } else {
        $error = 'Incorrect username or password.';
    }
}

$notice = match ($_GET['notice'] ?? '') {
    'logged_out' => 'You have been logged out.',
    default      => '',
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Admin Login | PhishGuard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="../assets/css/style.css" rel="stylesheet">
</head>
<body class="login-page">
<main class="d-flex align-items-center justify-content-center px-3">
    <div class="login-card card border-0 shadow">
        <div class="card-body p-4 p-md-5">
            <div class="text-center mb-4">
                <i class="bi bi-shield-lock-fill text-accent display-5"></i>
                <h1 class="h4 fw-bold mt-2 mb-1">Admin Login</h1>
                <p class="text-muted small mb-0">PhishGuard administration</p>
            </div>

            <?php if ($notice): ?>
                <div class="alert alert-success small py-2" role="status"><?= e($notice) ?></div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="alert alert-danger small py-2" role="alert"><?= e($error) ?></div>
            <?php endif; ?>

            <form method="POST" action="login.php">
                <?= csrfField() ?>
                <input type="hidden" name="next" value="<?= e($next) ?>">
                <div class="mb-3">
                    <label for="username" class="form-label fw-semibold">Username</label>
                    <input type="text" name="username" id="username" class="form-control" required
                           autocomplete="username" autofocus value="<?= e($username) ?>">
                </div>
                <div class="mb-4">
                    <label for="password" class="form-label fw-semibold">Password</label>
                    <input type="password" name="password" id="password" class="form-control" required
                           autocomplete="current-password">
                </div>
                <button type="submit" class="btn btn-accent w-100"><i class="bi bi-box-arrow-in-right"></i> Log in</button>
            </form>

            <div class="text-center mt-4">
                <a href="../index.php" class="small text-muted"><i class="bi bi-arrow-left"></i> Back to PhishGuard</a>
            </div>
        </div>
    </div>
</main>
</body>
</html>
