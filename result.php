<?php
require 'config/db.php';

$stmt = db()->prepare('SELECT * FROM scans WHERE id = ?');
$stmt->execute([(int) ($_GET['id'] ?? 0)]);
$scan = $stmt->fetch();

if (!$scan) {
    header('Location: index.php');
    exit;
}

$reasons = json_decode($scan['reasons'], true);

$verdicts = [
    'safe'       => ['label' => 'Looks Safe', 'color' => 'success', 'icon' => 'bi-shield-check',
                     'text' => 'We found no strong signs of phishing. Still be careful before entering passwords or payment details.'],
    'suspicious' => ['label' => 'Suspicious', 'color' => 'warning', 'icon' => 'bi-exclamation-triangle',
                     'text' => 'This link has some warning signs. Do not enter personal information unless you are sure it is genuine.'],
    'phishing'   => ['label' => 'Likely Phishing', 'color' => 'danger', 'icon' => 'bi-shield-x',
                     'text' => 'This link shows strong signs of phishing. Do not open it or enter any information.'],
];
$v = $verdicts[$scan['verdict']];

$pageTitle = 'Scan Result — PhishGuard';
require 'includes/header.php';
?>

<section class="container py-5">
    <div class="row justify-content-center">
        <div class="col-lg-8">
            <div class="card result-card border-<?= $v['color'] ?>">
                <div class="card-body p-4 p-md-5 text-center">
                    <i class="bi <?= $v['icon'] ?> text-<?= $v['color'] ?> verdict-icon"></i>
                    <h1 class="h3 fw-bold mt-3 text-<?= $v['color'] ?>"><?= $v['label'] ?></h1>
                    <p class="text-break text-muted mb-4"><code><?= htmlspecialchars($scan['url']) ?></code></p>

                    <div class="d-flex justify-content-between small fw-semibold mb-1">
                        <span>Risk score</span>
                        <span><?= (int) $scan['score'] ?> / 100</span>
                    </div>
                    <div class="progress mb-4" style="height: 12px;">
                        <div class="progress-bar bg-<?= $v['color'] ?>" style="width: <?= (int) $scan['score'] ?>%"></div>
                    </div>

                    <p class="mb-0"><?= $v['text'] ?></p>
                </div>
            </div>

            <h2 class="h5 fw-bold mt-5 mb-3">Why we gave this result</h2>
            <?php if (!$reasons): ?>
                <p class="text-muted">None of our phishing checks were triggered.</p>
            <?php else: ?>
                <ul class="list-group">
                    <?php foreach ($reasons as $reason): ?>
                        <li class="list-group-item d-flex justify-content-between align-items-start gap-3">
                            <span><?= htmlspecialchars($reason['message']) ?></span>
                            <?php if ($reason['points'] > 0): ?>
                                <span class="badge bg-secondary">+<?= (int) $reason['points'] ?></span>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <div class="text-center mt-4">
                <a href="index.php" class="btn btn-accent px-4"><i class="bi bi-arrow-repeat"></i> Scan another URL</a>
            </div>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
