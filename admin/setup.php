<?php
/**
 * First-run setup: create the first admin account.
 * Only works while no admin exists, and only from the computer running the site.
 */
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

$pdo = db();

if ((int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn() > 0) {
    header('Location: login.php');
    exit;
}

if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    exit('The first admin account can only be created on the computer running BaitCheck.');
}

$errors = [];
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Your session expired. Please try again.';
    } elseif (!preg_match('/^[A-Za-z0-9_]{3,50}$/', $username)) {
        $errors[] = 'Username must be 3 to 50 characters: letters, numbers or underscores.';
    } elseif (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters.';
    } elseif ($password !== ($_POST['confirm_password'] ?? '')) {
        $errors[] = 'The passwords do not match.';
    }

    if (!$errors) {
        $pdo->prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?) ON CONFLICT (username) DO NOTHING')
            ->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);

        attemptLogin($username, $password, $_SERVER['REMOTE_ADDR']);
        setFlash('success', 'Your admin account has been created and you are now logged in.');
        header('Location: index.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<?php
    $pageTitle = 'Admin Setup | BaitCheck';
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
                <span class="brand-mark brand-mark-lg"><i class="bi bi-person-plus-fill"></i></span>
                <h1 class="h4 fw-bold mt-2 mb-1">Create Admin Account</h1>
                <p class="text-muted small mb-0">No admin exists yet. Choose the login details for the first one.</p>
            </div>

            <?php if ($errors): ?>
                <div class="alert alert-danger small py-2" role="alert"><?= e($errors[0]) ?></div>
            <?php endif; ?>

            <form method="POST" action="setup.php">
                <?= csrfField() ?>
                <div class="mb-3">
                    <label for="username" class="form-label fw-semibold">Username</label>
                    <input type="text" name="username" id="username" class="form-control" required
                           pattern="[A-Za-z0-9_]{3,50}" autocomplete="username" autofocus value="<?= e($username) ?>">
                    <div class="form-text">Letters, numbers or underscores.</div>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label fw-semibold">Password</label>
                    <input type="password" name="password" id="password" class="form-control" required
                           minlength="8" autocomplete="new-password">
                    <div class="form-text">At least 8 characters.</div>
                </div>
                <div class="mb-4">
                    <label for="confirm_password" class="form-label fw-semibold">Confirm password</label>
                    <input type="password" name="confirm_password" id="confirm_password" class="form-control" required
                           minlength="8" autocomplete="new-password">
                </div>
                <button type="submit" class="btn btn-accent w-100"><i class="bi bi-check-lg"></i> Create account</button>
            </form>
        </div>
    </div>
</main>
<script src="../assets/js/main.js"></script>
</body>
</html>
