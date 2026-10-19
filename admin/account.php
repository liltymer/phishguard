<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

requireAdmin();

$pdo = db();
$stmt = $pdo->prepare("
    SELECT username, password_hash,
           DATE_FORMAT(created_at, '%e %b %Y') AS created,
           DATE_FORMAT(last_login_at, '%e %b %Y, %H:%i') AS last_login
    FROM admins WHERE id = ?
");
$stmt->execute([$_SESSION['admin_id']]);
$admin = $stmt->fetch();

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current = $_POST['current_password'] ?? '';
    $new = $_POST['new_password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Your session expired. Please try again.';
    } elseif (!password_verify($current, $admin['password_hash'])) {
        $errors[] = 'Your current password is incorrect.';
    } elseif (strlen($new) < 8) {
        $errors[] = 'The new password must be at least 8 characters.';
    } elseif ($new !== $confirm) {
        $errors[] = 'The new passwords do not match.';
    } elseif ($new === $current) {
        $errors[] = 'The new password must be different from the current one.';
    }

    if (!$errors) {
        $pdo->prepare('UPDATE admins SET password_hash = ? WHERE id = ?')
            ->execute([password_hash($new, PASSWORD_DEFAULT), $_SESSION['admin_id']]);
        session_regenerate_id(true);
        setFlash('success', 'Your password has been changed.');
        header('Location: account.php');
        exit;
    }
}

$pageTitle = 'Account | PhishGuard Admin';
$activePage = 'account';
require '../includes/admin_header.php';
?>

<h1 class="h3 fw-bold mb-4">Account</h1>

<div class="row g-4">
    <div class="col-lg-4">
        <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
                <h2 class="h6 fw-bold mb-3">Details</h2>
                <dl class="small mb-0">
                    <dt>Username</dt>
                    <dd><?= e($admin['username']) ?></dd>
                    <dt>Account created</dt>
                    <dd><?= e($admin['created']) ?></dd>
                    <dt>Current session started</dt>
                    <dd class="mb-0"><?= e($admin['last_login'] ?? 'Unknown') ?></dd>
                </dl>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
                <h2 class="h6 fw-bold mb-3">Change password</h2>

                <?php if ($errors): ?>
                    <div class="alert alert-danger small py-2" role="alert"><?= e($errors[0]) ?></div>
                <?php endif; ?>

                <form method="POST">
                    <?= csrfField() ?>
                    <div class="mb-3">
                        <label for="current_password" class="form-label small fw-semibold">Current password</label>
                        <input type="password" name="current_password" id="current_password" class="form-control"
                               required autocomplete="current-password">
                    </div>
                    <div class="mb-3">
                        <label for="new_password" class="form-label small fw-semibold">New password</label>
                        <input type="password" name="new_password" id="new_password" class="form-control"
                               required minlength="8" autocomplete="new-password">
                        <div class="form-text">At least 8 characters.</div>
                    </div>
                    <div class="mb-4">
                        <label for="confirm_password" class="form-label small fw-semibold">Confirm new password</label>
                        <input type="password" name="confirm_password" id="confirm_password" class="form-control"
                               required minlength="8" autocomplete="new-password">
                    </div>
                    <button class="btn btn-accent"><i class="bi bi-key"></i> Change password</button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require '../includes/footer.php'; ?>
