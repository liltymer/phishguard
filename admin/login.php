<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

// Only allow redirects to pages inside admin/, never to another website
$next = $_GET['next'] ?? $_POST['next'] ?? 'index.php';
if (!preg_match('/^[a-z_]+\.php$/', $next)) {
    $next = 'index.php';
}

// Fresh install with no admin yet: go to first-run setup
if ((int) db()->query('SELECT COUNT(*) FROM admins')->fetchColumn() === 0) {
    header('Location: setup.php');
    exit;
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
<?php
    $pageTitle = 'Admin Login | BaitCheck';
    $base = '../';
    require '../includes/head.php';
    ?>
    <meta name="robots" content="noindex, nofollow">
</head>
<body class="login-page">
<div class="theme-toggle-corner"><?php require '../includes/theme_toggle.php'; ?></div>
<main class="d-flex align-items-center justify-content-center px-3">
    <div class="login-card card">
        <div class="card-body p-4 p-md-5">
            <div class="text-center mb-4">
                <span class="brand-mark brand-mark-lg"><i class="bi bi-shield-fill-check"></i></span>
                <h1 class="h4 fw-bold mt-2 mb-1">Admin Login</h1>
                <p class="text-muted small mb-0">BaitCheck administration</p>
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
                <a href="../index.php" class="small text-muted"><i class="bi bi-arrow-left"></i> Back to BaitCheck</a>
            </div>
        </div>
    </div>
</main>
<script src="../assets/js/main.js"></script>
</body>
</html>
