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

// Scans per day for the last 7 days, using the database's date so time zones cannot disagree
$today = new DateTime($pdo->query('SELECT CURRENT_DATE')->fetchColumn());
$days = [];
for ($i = 6; $i >= 0; $i--) {
    $day = (clone $today)->modify("-$i day");
    $days[$day->format('Y-m-d')] = ['label' => $day->format('D'), 'date' => $day->format('j M'),
                                    'safe' => 0, 'suspicious' => 0, 'phishing' => 0];
}
$rows = $pdo->query("
    SELECT created_at::date AS day, verdict, COUNT(*) AS n
    FROM scans WHERE created_at >= CURRENT_DATE - INTERVAL '6 days'
    GROUP BY day, verdict
");
foreach ($rows as $row) {
    $days[$row['day']][$row['verdict']] = (int) $row['n'];
}
$dayTotals = array_map(fn($d) => $d['safe'] + $d['suspicious'] + $d['phishing'], $days);
$maxDay = max(1, max($dayTotals));
$weekTotal = array_sum($dayTotals);

$pendingReports = $pdo->query("
    SELECT id, url, type, EXTRACT(EPOCH FROM now() - created_at)::int AS age
    FROM reports WHERE status = 'pending' ORDER BY created_at DESC LIMIT 5
")->fetchAll();

$topDomains = $pdo->query("
    SELECT domain, COUNT(*) AS n, MAX(score) AS max_score
    FROM scans WHERE verdict = 'phishing'
    GROUP BY domain ORDER BY n DESC, max_score DESC LIMIT 5
")->fetchAll();

$series = ['safe', 'suspicious', 'phishing'];

$pageTitle = 'Dashboard | BaitCheck Admin';
$activePage = 'dashboard';
require '../includes/admin_header.php';
?>

<div class="page-head reveal">
    <div>
        <span class="section-eyebrow">Admin</span>
        <h1 class="page-title">Dashboard</h1>
        <p class="text-soft mb-0">Welcome back, <?= e($_SESSION['admin_username']) ?>. Here is what is happening on BaitCheck.</p>
    </div>
    <?php if ($stats['pending'] > 0): ?>
        <a href="reports.php" class="btn btn-accent"><i class="bi bi-flag"></i> Review <?= (int) $stats['pending'] ?> report<?= $stats['pending'] > 1 ? 's' : '' ?></a>
    <?php endif; ?>
</div>

<div class="row g-3 mb-4">
    <?php
    $cards = [
        ['Total scans', $stats['scans'], 'bi-search', 'navy', null, $weekTotal . ' in the last 7 days'],
        ['Phishing detected', $stats['phishing'], 'bi-shield-x', 'danger', null, (int) $stats['suspicious'] . ' more were suspicious'],
        ['Pending reports', $stats['pending'], 'bi-flag', 'warning', 'reports.php', $stats['pending'] ? 'Waiting for your review' : 'All caught up'],
        ['Blacklisted domains', $stats['blacklist'], 'bi-slash-circle', 'navy', 'lists.php?list=blacklist', (int) $stats['whitelist'] . ' on the trusted list'],
    ];
    foreach ($cards as $i => [$label, $value, $icon, $color, $link, $sub]): ?>
        <div class="col-6 col-lg-3 reveal" style="--d: <?= $i * 80 ?>ms">
            <div class="card stat-card stat-<?= $color ?> h-100 <?= $link ? 'stat-filter' : '' ?>">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <span class="stat-chip"><i class="bi <?= $icon ?>"></i></span>
                        <?php if ($link): ?><i class="bi bi-arrow-up-right text-muted small" aria-hidden="true"></i><?php endif; ?>
                    </div>
                    <div class="stat-value" data-count="<?= (int) $value ?>"><?= number_format((int) $value) ?></div>
                    <div class="fw-semibold small">
                        <?php if ($link): ?>
                            <a href="<?= $link ?>" class="stretched-link text-reset text-decoration-none"><?= $label ?></a>
                        <?php else: ?>
                            <?= $label ?>
                        <?php endif; ?>
                    </div>
                    <div class="small text-muted"><?= e($sub) ?></div>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
</div>

<div class="row g-4">
    <div class="col-lg-8 reveal" style="--d: 120ms">
        <div class="card h-100">
            <div class="card-body p-4">
                <div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
                    <div>
                        <h2 class="h6 fw-bold mb-1">Scans in the last 7 days</h2>
                        <span class="text-muted small"><?= $weekTotal ?> scan<?= $weekTotal === 1 ? '' : 's' ?> in total</span>
                    </div>
                    <ul class="chart-legend list-unstyled d-flex flex-wrap gap-3 small mb-0">
                        <?php foreach ($series as $key): $info = verdictInfo($key); ?>
                            <li><span class="swatch swatch-<?= $key ?>"></span> <?= $info['short'] ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <?php if ($weekTotal === 0): ?>
                    <div class="text-center py-5">
                        <span class="icon-chip icon-chip-lg mx-auto"><i class="bi bi-bar-chart"></i></span>
                        <p class="text-muted mb-0">No scans in the last 7 days.</p>
                    </div>
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

    <div class="col-lg-4 d-flex flex-column gap-4">
        <div class="card reveal" style="--d: 200ms">
            <div class="card-body p-4">
                <div class="d-flex justify-content-between align-items-baseline mb-3">
                    <h2 class="h6 fw-bold mb-0">Latest pending reports</h2>
                    <a href="reports.php" class="small link-arrow">View all <i class="bi bi-arrow-right"></i></a>
                </div>
                <?php if (!$pendingReports): ?>
                    <div class="d-flex align-items-center gap-3 small text-muted">
                        <span class="url-avatar verdict-safe"><i class="bi bi-check-lg"></i></span>
                        Nothing waiting for review.
                    </div>
                <?php else: ?>
                    <ul class="mini-list list-unstyled mb-0">
                        <?php foreach ($pendingReports as $report):
                            $isPhishing = $report['type'] === 'phishing'; ?>
                            <li>
                                <span class="url-avatar verdict-<?= $isPhishing ? 'phishing' : 'safe' ?>">
                                    <i class="bi <?= $isPhishing ? 'bi-flag-fill' : 'bi-hand-thumbs-up-fill' ?>"></i>
                                </span>
                                <div class="min-w-0 flex-grow-1">
                                    <div class="font-monospace small text-truncate" title="<?= e($report['url']) ?>"><?= e($report['url']) ?></div>
                                    <div class="small text-muted"><?= $isPhishing ? 'Phishing report' : 'False alarm' ?> &middot; <?= timeAgo((int) $report['age']) ?></div>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </div>

        <div class="card flex-grow-1 reveal" style="--d: 280ms">
            <div class="card-body p-4">
                <h2 class="h6 fw-bold mb-3">Most detected phishing domains</h2>
                <?php if (!$topDomains): ?>
                    <p class="text-muted small mb-0">No phishing detected yet.</p>
                <?php else: $topMax = max(array_column($topDomains, 'n')); ?>
                    <ol class="rank-list list-unstyled mb-0">
                        <?php foreach ($topDomains as $rank => $row): ?>
                            <li>
                                <span class="rank-num"><?= $rank + 1 ?></span>
                                <div class="min-w-0 flex-grow-1">
                                    <div class="d-flex justify-content-between gap-2 small">
                                        <span class="font-monospace text-truncate" title="<?= e($row['domain']) ?>"><?= e($row['domain']) ?></span>
                                        <span class="text-muted text-nowrap"><?= (int) $row['n'] ?> scan<?= $row['n'] > 1 ? 's' : '' ?></span>
                                    </div>
                                    <div class="share-bar verdict-phishing" aria-hidden="true"><span style="width: <?= round($row['n'] / $topMax * 100) ?>%"></span></div>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ol>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require '../includes/footer.php'; ?>
