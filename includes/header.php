<?php
$pageTitle = $pageTitle ?? 'PhishGuard';
$activePage = $activePage ?? '';

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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-navy">
    <div class="container">
        <a class="navbar-brand fw-bold" href="index.php">
            <i class="bi bi-shield-lock-fill text-accent"></i> PhishGuard
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav"
                aria-controls="mainNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="mainNav">
            <ul class="navbar-nav ms-auto">
                <?php foreach ($navItems as $key => $item): ?>
                    <li class="nav-item">
                        <a class="nav-link <?= $activePage === $key ? 'active' : '' ?>" href="<?= $item['href'] ?>"
                            <?= $activePage === $key ? 'aria-current="page"' : '' ?>><?= $item['label'] ?></a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</nav>
<main>
