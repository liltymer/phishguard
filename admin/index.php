<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

requireAdmin();

$pdo = db();

$stats = $pdo->query("
    SELECT
        (SELECT COUNT(*) FROM scans)                              AS scans,
        (SELECT COUNT(*) FROM scans WHERE verdict = 'phishing')   AS phishing,
        (SELECT COUNT(*) FROM scans WHERE verdict = 'suspicious') AS suspicious,
        (SELECT COUNT(*) FROM reports WHERE status = 'pending')   AS pending,
        (SELECT COUNT(*) FROM blacklist)                          AS blacklist,
        (SELECT COUNT(*) FROM whitelist)                          AS whitelist
")->fetch();

// Scans per day for the last 7 days, using MySQL's date so time zones cannot disagree
$today = new DateTime($pdo->query('SELECT CURDATE()')->fetchColumn());
$days = [];
for ($i = 6; $i >= 0; $i--) {
    $day = (clone $today)->modify("-$i day");
    $days[$day->format('Y-m-d')] = ['label' => $day->format('D'), 'date' => $day->format('j M'),
                                    'safe' => 0, 'suspicious' => 0, 'phishing' => 0];
}
$rows = $pdo->query("
    SELECT DATE(created_at) AS day, verdict, COUNT(*) AS n
    FROM scans WHERE created_at >= CURDATE() - INTERVAL 6 DAY
    GROUP BY day, verdict
");
foreach ($rows as $row) {
    $days[$row['day']][$row['verdict']] = (int) $row['n'];
}
$dayTotals = array_map(fn($d) => $d['safe'] + $d['suspicious'] + $d['phishing'], $days);
$maxDay = max(1, max($dayTotals));
$weekTotal = array_sum($dayTotals);

$pendingReports = $pdo->query("
    SELECT id, url, type, TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age
    FROM reports WHERE status = 'pending' ORDER BY created_at DESC LIMIT 5
")->fetchAll();

$topDomains = $pdo->query("
    SELECT domain, COUNT(*) AS n, MAX(score) AS max_score
    FROM scans WHERE verdict = 'phishing'
    GROUP BY domain ORDER BY n DESC, max_score DESC LIMIT 5
")->fetchAll();

$series = ['safe', 'suspicious', 'phishing'];

$pageTitle = 'Dashboard | PhishGuard Admin';
$activePage = 'dashboard';
require '../includes/admin_header.php';
?>

<div class="d-flex flex-wrap justify-content-between align-items-center mb-4 gap-2">
    <h1 class="h3 fw-bold mb-0">Dashboard</h1>
    <span class="text-muted small">Welcome back, <?= e($_SESSION['admin_username']) ?></span>
</div>

<div class="row g-3 mb-4">
    <?php
    $cards = [
        ['Total scans', $stats['scans'], 'bi-search', 'navy', null],
        ['Phishing detected', $stats['phishing'], 'bi-shield-x', 'danger', null],
        ['Pending reports', $stats['pending'], 'bi-flag', 'warning', 'reports.php'],
        ['Blacklisted domains', $stats['blacklist'], 'bi-slash-circle', 'navy', 'lists.php?list=blacklist'],
    ];
    foreach ($cards as [$label, $value, $icon, $color, $link]): ?>
        <div class="col-6 col-lg-3">
            <div class="card stat-card stat-<?= $color ?> h-100"><div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="stat-value"><?= number_format((int) $value) ?></div>
                    <i class="bi <?= $icon ?> stat-icon"></i>
                </div>
                <div class="text-muted small">
                    <?php if ($link): ?>
                        <a href="<?= $link ?>" class="stretched-link text-reset text-decoration-none"><?= $label ?></a>
                    <?php else: ?>
                        <?= $label ?>
                    <?php endif; ?>
                </div>
            </div></div>
        </div>
    <?php endforeach; ?>
</div>

<div class="row g-4">
    <div class="col-lg-8">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body p-4">
                <div class="d-flex flex-wrap justify-content-between align-items-baseline gap-2 mb-3">
                    <h2 class="h6 fw-bold mb-0">Scans in the last 7 days</h2>
                    <span class="text-muted small"><?= $weekTotal ?> total</span>
                </div>

                <ul class="chart-legend list-unstyled d-flex flex-wrap gap-3 small mb-3">
                    <?php foreach ($series as $key): $info = verdictInfo($key); ?>
                        <li><span class="swatch swatch-<?= $key ?>"></span> <i class="bi <?= $info['icon'] ?>"></i> <?= $info['short'] ?></li>
                    <?php endforeach; ?>
                </ul>

                <?php if ($weekTotal === 0): ?>
                    <p class="text-muted text-center py-5 mb-0">No scans in the last 7 days.</p>
                <?php else: ?>
                    <div class="chart" role="img" aria-label="Stacked bar chart of scans per day by verdict. A table view follows.">
                        <div class="chart-tip" hidden></div>
                        <?php foreach ($days as $day):
                            $total = $day['safe'] + $day['suspicious'] + $day['phishing']; ?>
                            <div class="chart-col" tabindex="0"
                                 data-date="<?= e($day['label'] . ' ' . $day['date']) ?>"
                                 data-safe="<?= $day['safe'] ?>" data-suspicious="<?= $day['suspicious'] ?>"
                                 data-phishing="<?= $day['phishing'] ?>">
                                <span class="chart-total"><?= $total ?: '' ?></span>
                                <div class="chart-track">
                                    <div class="chart-stack" style="height: <?= round($total / $maxDay * 100, 1) ?>%">
                                        <?php foreach ($series as $key): if ($day[$key] > 0): ?>
                                            <div class="seg seg-<?= $key ?>" style="flex-grow: <?= $day[$key] ?>"></div>
                                        <?php endif; endforeach; ?>
                                    </div>
                                </div>
                                <span class="chart-day"><?= $day['label'] ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <details class="mt-3 small">
                        <summary class="text-muted">View as table</summary>
                        <table class="table table-sm mt-2 mb-0">
                            <thead><tr><th>Day</th><th class="text-end">Safe</th><th class="text-end">Suspicious</th><th class="text-end">Phishing</th><th class="text-end">Total</th></tr></thead>
                            <tbody>
                                <?php foreach ($days as $day): ?>
                                    <tr>
                                        <td><?= e($day['label'] . ' ' . $day['date']) ?></td>
                                        <td class="text-end"><?= $day['safe'] ?></td>
                                        <td class="text-end"><?= $day['suspicious'] ?></td>
                                        <td class="text-end"><?= $day['phishing'] ?></td>
                                        <td class="text-end fw-semibold"><?= $day['safe'] + $day['suspicious'] + $day['phishing'] ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </details>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-4">
        <div class="card border-0 shadow-sm mb-4">
            <div class="card-body p-4">
                <div class="d-flex justify-content-between align-items-baseline mb-3">
                    <h2 class="h6 fw-bold mb-0">Latest pending reports</h2>
                    <a href="reports.php" class="small">View all</a>
                </div>
                <?php if (!$pendingReports): ?>
                    <p class="text-muted small mb-0"><i class="bi bi-check-circle text-success"></i> Nothing waiting for review.</p>
                <?php else: ?>
                    <ul class="list-unstyled mb-0">
                        <?php foreach ($pendingReports as $report): ?>
                            <li class="d-flex justify-content-between gap-2 py-2 border-bottom small">
                                <span class="text-truncate font-monospace" title="<?= e($report['url']) ?>"><?= e($report['url']) ?></span>
                                <span class="text-muted text-nowrap"><?= timeAgo((int) $report['age']) ?></span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </div>

        <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
                <h2 class="h6 fw-bold mb-3">Most detected phishing domains</h2>
                <?php if (!$topDomains): ?>
                    <p class="text-muted small mb-0">No phishing detected yet.</p>
                <?php else: ?>
                    <ol class="small ps-3 mb-0">
                        <?php foreach ($topDomains as $row): ?>
                            <li class="py-1">
                                <span class="font-monospace"><?= e($row['domain']) ?></span>
                                <span class="text-muted">(<?= (int) $row['n'] ?> scan<?= $row['n'] > 1 ? 's' : '' ?>)</span>
                            </li>
                        <?php endforeach; ?>
                    </ol>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require '../includes/footer.php'; ?>
