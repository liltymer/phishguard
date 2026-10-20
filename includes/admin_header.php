<?php
// Layout for pages inside admin/. Requires requireAdmin() to have run.
$pageTitle = $pageTitle ?? 'Admin | BaitCheck';
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
<?php require __DIR__ . '/head.php'; ?>
    <meta name="robots" content="noindex, nofollow">
</head>
<body class="admin">
<a href="#main" class="visually-hidden-focusable skip-link">Skip to content</a>
<nav class="navbar navbar-expand-xl site-nav sticky-top">
    <div class="container">
        <a class="navbar-brand brand" href="index.php">
            <span class="brand-mark"><i class="bi bi-shield-fill-check"></i></span> <span>Bait<span class="text-gradient">Check</span></span> <span class="badge bg-accent-soft d-none d-sm-inline-block">Admin</span>
        </a>
        <div class="d-flex align-items-center gap-2 order-xl-last ms-auto ms-xl-3">
            <?php require __DIR__ . '/theme_toggle.php'; ?>
            <!-- Account menu: who is signed in, a link back to the public site, and log out -->
            <div class="dropdown">
                <button class="btn user-chip dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false"
                        aria-label="Account menu for <?= e($_SESSION['admin_username']) ?>">
                    <span class="avatar"><?= e(strtoupper(substr($_SESSION['admin_username'], 0, 1))) ?></span>
                    <span class="d-none d-md-inline"><?= e($_SESSION['admin_username']) ?></span>
                </button>
                <ul class="dropdown-menu dropdown-menu-end">
                    <li><span class="dropdown-header">Signed in as <strong><?= e($_SESSION['admin_username']) ?></strong></span></li>
                    <li><a class="dropdown-item" href="../index.php"><i class="bi bi-box-arrow-up-right"></i> View public site</a></li>
                    <li><a class="dropdown-item" href="account.php"><i class="bi bi-key"></i> Change password</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li>
                        <form method="POST" action="logout.php" class="m-0">
                            <?= csrfField() ?>
                            <button class="dropdown-item dropdown-item-danger"><i class="bi bi-box-arrow-right"></i> Log out</button>
                        </form>
                    </li>
                </ul>
            </div>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#adminNav"
                    aria-controls="adminNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
        </div>
        <div class="collapse navbar-collapse" id="adminNav">
            <ul class="navbar-nav ms-xl-4 me-auto gap-xl-1">
                <?php foreach ($adminNav as $key => $item): ?>
                    <li class="nav-item">
                        <a class="nav-link <?= $activePage === $key ? 'active' : '' ?>" href="<?= $item['href'] ?>"
                            <?= $activePage === $key ? 'aria-current="page"' : '' ?>>
                            <i class="bi <?= $item['icon'] ?>"></i> <?= $item['label'] ?>
                            <?php if ($key === 'reports' && $pendingCount > 0): ?>
                                <span class="nav-count" aria-label="<?= $pendingCount ?> pending"><?= $pendingCount ?></span>
                            <?php endif; ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</nav>
<main id="main" class="container page-section">
    <?= flashMessage() ?>
