<?php
// Layout for pages inside admin/. Requires requireAdmin() to have run.
$pageTitle = $pageTitle ?? 'Admin | PhishGuard';
$activePage = $activePage ?? '';
$base = '../';

$pendingCount = (int) db()->query("SELECT COUNT(*) FROM reports WHERE status = 'pending'")->fetchColumn();

$adminNav = [
    'dashboard' => ['href' => 'index.php',   'label' => 'Dashboard', 'icon' => 'bi-speedometer2'],
    'reports'   => ['href' => 'reports.php', 'label' => 'Reports',   'icon' => 'bi-flag'],
    'lists'     => ['href' => 'lists.php',   'label' => 'Domain Lists', 'icon' => 'bi-list-ul'],
    'account'   => ['href' => 'account.php', 'label' => 'Account',   'icon' => 'bi-person-gear'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?= e($pageTitle) ?></title>
    <link rel="icon" href="../assets/img/favicon.svg" type="image/svg+xml">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="../assets/css/style.css" rel="stylesheet">
</head>
<body class="admin">
<a href="#main" class="visually-hidden-focusable skip-link">Skip to content</a>
<nav class="navbar navbar-expand-lg navbar-dark bg-navy">
    <div class="container">
        <a class="navbar-brand fw-bold" href="index.php">
            <i class="bi bi-shield-lock-fill text-accent"></i> PhishGuard <span class="badge bg-accent-soft ms-1">Admin</span>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#adminNav"
                aria-controls="adminNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="adminNav">
            <ul class="navbar-nav me-auto">
                <?php foreach ($adminNav as $key => $item): ?>
                    <li class="nav-item">
                        <a class="nav-link <?= $activePage === $key ? 'active' : '' ?>" href="<?= $item['href'] ?>"
                            <?= $activePage === $key ? 'aria-current="page"' : '' ?>>
                            <i class="bi <?= $item['icon'] ?>"></i> <?= $item['label'] ?>
                            <?php if ($key === 'reports' && $pendingCount > 0): ?>
                                <span class="badge rounded-pill text-bg-warning ms-1"><?= $pendingCount ?></span>
                            <?php endif; ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
            <div class="d-flex align-items-center gap-3">
                <a href="../index.php" class="nav-link text-light-50 small"><i class="bi bi-box-arrow-up-right"></i> View site</a>
                <span class="text-light-50 small d-none d-lg-inline">
                    <i class="bi bi-person-circle"></i> <?= e($_SESSION['admin_username']) ?>
                </span>
                <form method="POST" action="logout.php" class="m-0">
                    <?= csrfField() ?>
                    <button class="btn btn-sm btn-outline-light"><i class="bi bi-box-arrow-right"></i> Log out</button>
                </form>
            </div>
        </div>
    </div>
</nav>
<main id="main" class="container py-4">
    <?= flashMessage() ?>
