<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

requireAdmin();

$pdo = db();
$stmt = $pdo->prepare("
    SELECT username, password_hash,
           to_char(created_at, 'FMDD Mon YYYY') AS created,
           to_char(last_login_at, 'FMDD Mon YYYY, HH24:MI') AS last_login
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

$pageTitle = 'Account | BaitCheck Admin';
$activePage = 'account';
require '../includes/admin_header.php';
?>

<div class="page-head reveal">
    <div>
        <span class="section-eyebrow">Admin</span>
        <h1 class="page-title">Account</h1>
        <p class="text-soft mb-0">Your administrator details and password.</p>
    </div>
</div>

<div class="row g-4">
    <div class="col-lg-4 reveal" style="--d: 80ms">
        <div class="card profile-card h-100">
            <div class="card-body p-4 text-center">
                <span class="avatar avatar-xl mx-auto mb-3"><?= e(strtoupper(substr($admin['username'], 0, 1))) ?></span>
                <h2 class="h5 fw-bold mb-1"><?= e($admin['username']) ?></h2>
                <span class="badge bg-accent-soft">Administrator</span>
                <dl class="profile-details text-start small mt-4 mb-0">
                    <div><dt><i class="bi bi-calendar3"></i> Account created</dt><dd><?= e($admin['created']) ?></dd></div>
                    <div><dt><i class="bi bi-clock-history"></i> Current session started</dt><dd><?= e($admin['last_login'] ?? 'Unknown') ?></dd></div>
                </dl>
            </div>
        </div>
    </div>

    <div class="col-lg-8 reveal" style="--d: 160ms">
        <div class="card h-100">
            <div class="card-body p-4 p-md-5">
                <div class="d-flex align-items-center gap-3 mb-4">
                    <span class="icon-chip"><i class="bi bi-key"></i></span>
                    <div>
                        <h2 class="h6 fw-bold mb-0">Change password</h2>
                        <span class="small text-muted">You will stay signed in after changing it.</span>
                    </div>
                </div>

                <?php if ($errors): ?>
                    <div class="notice notice-error mb-4" role="alert">
                        <span class="notice-icon"><i class="bi bi-exclamation-lg"></i></span>
                        <div><?= e($errors[0]) ?></div>
                    </div>
                <?php endif; ?>

                <form method="POST">
                    <?= csrfField() ?>
                    <?php
                    $fields = [
                        ['current_password', 'Current password', 'current-password', ''],
                        ['new_password', 'New password', 'new-password', 'At least 8 characters.'],
                        ['confirm_password', 'Confirm new password', 'new-password', ''],
                    ];
                    foreach ($fields as [$name, $label, $autocomplete, $help]): ?>
                        <div class="mb-3">
                            <label for="<?= $name ?>" class="form-label small fw-semibold"><?= $label ?></label>
                            <div class="field-icon field-password">
                                <i class="bi bi-lock" aria-hidden="true"></i>
                                <input type="password" name="<?= $name ?>" id="<?= $name ?>" class="form-control"
                                       required <?= $name !== 'current_password' ? 'minlength="8"' : '' ?> autocomplete="<?= $autocomplete ?>">
                                <button type="button" class="btn-reveal" data-toggle-password="<?= $name ?>" aria-label="Show password">
                                    <i class="bi bi-eye"></i>
                                </button>
                            </div>
                            <?php if ($help): ?><div class="form-text"><?= $help ?></div><?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                    <button class="btn btn-accent mt-2"><i class="bi bi-check-lg"></i> Change password</button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require '../includes/footer.php'; ?>
