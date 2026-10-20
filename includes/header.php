<?php
$pageTitle = $pageTitle ?? 'BaitCheck';
$activePage = $activePage ?? '';
$base = $base ?? '';   // '../' for pages inside a subfolder such as admin/
$pageDescription = $pageDescription
    ?? 'BaitCheck checks links for phishing before you click: paste a URL to get a risk score and a clear explanation.';

$navItems = [
    'scan'    => ['href' => 'index.php',   'label' => 'Scan URL'],
    'history' => ['href' => 'history.php', 'label' => 'History'],
    'report'  => ['href' => 'report.php',  'label' => 'Report URL'],
    'about'   => ['href' => 'about.php',   'label' => 'How It Works'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<?php require __DIR__ . '/head.php'; ?>
    <meta name="description" content="<?= htmlspecialchars($pageDescription) ?>">
</head>
<body>
<a href="#main" class="visually-hidden-focusable skip-link">Skip to content</a>
<nav class="navbar navbar-expand-lg site-nav sticky-top">
    <div class="container">
        <a class="navbar-brand brand" href="<?= $base ?>index.php">
            <span class="brand-mark"><i class="bi bi-shield-fill-check"></i></span> <span>Bait<span class="text-gradient">Check</span></span>
        </a>
        <div class="d-flex align-items-center gap-1 order-lg-last ms-auto ms-lg-2">
            <?php require __DIR__ . '/theme_toggle.php'; ?>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav"
                    aria-controls="mainNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
        </div>
        <div class="collapse navbar-collapse" id="mainNav">
            <ul class="navbar-nav ms-auto">
                <?php foreach ($navItems as $key => $item): ?>
                    <li class="nav-item">
                        <a class="nav-link <?= $activePage === $key ? 'active' : '' ?>" href="<?= $base . $item['href'] ?>"
                            <?= $activePage === $key ? 'aria-current="page"' : '' ?>><?= $item['label'] ?></a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</nav>
<main id="main">
