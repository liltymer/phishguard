<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';
require '../includes/Detector.php';

requireAdmin();

$pdo = db();

/**
 * Confirm a report: add the domain to the right list, take it off the opposite
 * list, and close every pending report of the same kind for that domain.
 */
function confirmReport(PDO $pdo, array $report, string $target): int
{
    $isPhishing = $report['type'] === 'phishing';
    $addTo = $isPhishing ? 'blacklist' : 'whitelist';
    $removeFrom = $isPhishing ? 'whitelist' : 'blacklist';
    $note = 'Confirmed from user report #' . $report['id'];

    $pdo->beginTransaction();
    try {
        $pdo->prepare("DELETE FROM $removeFrom WHERE domain = ?")->execute([$target]);
        $pdo->prepare("INSERT INTO $addTo (domain, note) VALUES (?, ?) ON CONFLICT (domain) DO UPDATE SET note = EXCLUDED.note")
            ->execute([$target, $note]);

        $close = $pdo->prepare("
            UPDATE reports SET status = 'confirmed', reviewed_at = now()
            WHERE status = 'pending' AND type = ? AND (domain = ? OR domain LIKE ?)
        ");
        $close->execute([$report['type'], $target, '%.' . addcslashes($target, '%_\\')]);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return $close->rowCount();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $redirect = 'reports.php?' . http_build_query(array_filter([
        'status' => $_POST['return_status'] ?? '',
        'type'   => $_POST['return_type'] ?? '',
    ]));

    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        setFlash('danger', 'Your session expired. Please try again.');
        header("Location: $redirect");
        exit;
    }

    $stmt = $pdo->prepare("SELECT * FROM reports WHERE id = ? AND status = 'pending'");
    $stmt->execute([(int) ($_POST['report_id'] ?? 0)]);
    $report = $stmt->fetch();

    if (!$report) {
        setFlash('warning', 'That report has already been reviewed.');
    } elseif (($_POST['action'] ?? '') === 'reject') {
        $pdo->prepare("UPDATE reports SET status = 'rejected', reviewed_at = now() WHERE id = ?")->execute([$report['id']]);
        setFlash('success', 'Report #' . $report['id'] . ' rejected. No lists were changed.');
    } elseif (($_POST['action'] ?? '') === 'confirm') {
        // The admin chooses between the exact host and the whole registrable domain
        $target = ($_POST['scope'] ?? 'host') === 'domain'
            ? Detector::registrableDomain($report['domain'])
            : $report['domain'];

        $closed = confirmReport($pdo, $report, $target);
        $list = $report['type'] === 'phishing' ? 'blacklist' : 'trusted list';
        setFlash('success', "\"$target\" added to the $list. $closed report" . ($closed > 1 ? 's' : '') . ' marked as confirmed.');
    }

    header("Location: $redirect");
    exit;
}

$statusFilter = $_GET['status'] ?? 'pending';
if (!in_array($statusFilter, ['pending', 'confirmed', 'rejected', 'all'], true)) {
    $statusFilter = 'pending';
}
$typeFilter = $_GET['type'] ?? 'all';
if (!in_array($typeFilter, ['all', 'phishing', 'false_positive'], true)) {
    $typeFilter = 'all';
}

$where = [];
$params = [];
if ($statusFilter !== 'all') {
    $where[] = 'r.status = ?';
    $params[] = $statusFilter;
}
if ($typeFilter !== 'all') {
    $where[] = 'r.type = ?';
    $params[] = $typeFilter;
}
$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$stmt = $pdo->prepare("
    SELECT r.*, EXTRACT(EPOCH FROM now() - r.created_at)::int AS age,
           s.verdict AS scan_verdict, s.score AS scan_score,
           (SELECT COUNT(*) FROM reports o WHERE o.domain = r.domain AND o.type = r.type AND o.status = 'pending') AS similar
    FROM reports r
    LEFT JOIN scans s ON s.id = r.scan_id
    $whereSql
    ORDER BY r.created_at DESC
    LIMIT 100
");
$stmt->execute($params);
$reports = $stmt->fetchAll();

$typeInfo = [
    'phishing'       => ['label' => 'Phishing report', 'color' => 'danger', 'icon' => 'bi-flag-fill'],
    'false_positive' => ['label' => 'False alarm', 'color' => 'success', 'icon' => 'bi-hand-thumbs-up-fill'],
];
$statusColors = ['pending' => 'warning', 'confirmed' => 'success', 'rejected' => 'secondary'];

$pageTitle = 'Reports | BaitCheck Admin';
$activePage = 'reports';
require '../includes/admin_header.php';
?>

<?php
// Counts for the status tabs (all report types)
$statusCounts = ['pending' => 0, 'confirmed' => 0, 'rejected' => 0];
foreach ($pdo->query('SELECT status, COUNT(*) AS n FROM reports GROUP BY status') as $row) {
    $statusCounts[$row['status']] = (int) $row['n'];
}
$statusCounts['all'] = array_sum($statusCounts);
$filterLink = fn(array $changes) => 'reports.php?' . http_build_query(array_merge(['status' => $statusFilter, 'type' => $typeFilter], $changes));
?>

<div class="page-head reveal">
    <div>
        <span class="section-eyebrow">Admin</span>
        <h1 class="page-title">User reports</h1>
        <p class="text-soft mb-0">Confirm a report to add the domain to the blacklist or trusted list, or reject it.</p>
    </div>
</div>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-4 reveal" style="--d: 80ms">
    <nav class="seg-tabs" aria-label="Filter by status">
        <?php foreach (['pending' => 'Pending', 'confirmed' => 'Confirmed', 'rejected' => 'Rejected', 'all' => 'All'] as $key => $label): ?>
            <a href="<?= e($filterLink(['status' => $key])) ?>" class="<?= $statusFilter === $key ? 'active' : '' ?>"
               <?= $statusFilter === $key ? 'aria-current="page"' : '' ?>>
                <?= $label ?> <span class="seg-count"><?= $statusCounts[$key] ?></span>
            </a>
        <?php endforeach; ?>
    </nav>
    <nav class="seg-tabs seg-tabs-sm" aria-label="Filter by type">
        <a href="<?= e($filterLink(['type' => 'all'])) ?>" class="<?= $typeFilter === 'all' ? 'active' : '' ?>">All types</a>
        <?php foreach ($typeInfo as $key => $info): ?>
            <a href="<?= e($filterLink(['type' => $key])) ?>" class="<?= $typeFilter === $key ? 'active' : '' ?>">
                <i class="bi <?= $info['icon'] ?>"></i> <?= $info['label'] ?>
            </a>
        <?php endforeach; ?>
    </nav>
</div>

<?php if (!$reports): ?>
    <div class="card text-center reveal">
        <div class="card-body py-5">
            <span class="icon-chip icon-chip-lg mx-auto"><i class="bi bi-inbox"></i></span>
            <h2 class="h5 fw-bold mt-2"><?= $statusFilter === 'pending' ? 'All caught up' : 'No reports here' ?></h2>
            <p class="text-muted mb-0"><?= $statusFilter === 'pending' ? 'No reports are waiting for review.' : 'No reports match these filters.' ?></p>
        </div>
    </div>
<?php endif; ?>

<?php foreach ($reports as $n => $report):
    $type = $typeInfo[$report['type']];
    $domain = $report['domain'];
    $registrable = Detector::registrableDomain($domain);
    $listName = $report['type'] === 'phishing' ? 'blacklist' : 'trusted list'; ?>
    <div class="card report-card mb-3 row-in verdict-<?= $report['type'] === 'phishing' ? 'phishing' : 'safe' ?>" style="--d: <?= 120 + $n * 60 ?>ms">
        <div class="card-body p-4">
            <div class="d-flex gap-3">
                <span class="url-avatar"><i class="bi <?= $type['icon'] ?>"></i></span>
                <div class="min-w-0 flex-grow-1">
                    <div class="d-flex flex-wrap justify-content-between gap-2 mb-1">
                        <div class="d-flex flex-wrap gap-2 align-items-center">
                            <span class="badge text-bg-<?= $type['color'] ?>"><?= $type['label'] ?></span>
                            <span class="badge text-bg-<?= $statusColors[$report['status']] ?>"><?= ucfirst($report['status']) ?></span>
                            <span class="text-muted small">#<?= (int) $report['id'] ?> &middot; <?= timeAgo((int) $report['age']) ?></span>
                        </div>
                        <?php if ($report['status'] === 'pending' && $report['similar'] > 1): ?>
                            <span class="small text-muted"><i class="bi bi-people"></i> <?= (int) $report['similar'] ?> pending reports for this domain</span>
                        <?php endif; ?>
                    </div>

                    <p class="report-url font-monospace text-break mb-2"><?= e($report['url']) ?></p>

                    <?php if ($report['reason']): ?>
                        <blockquote class="report-reason small mb-2"><?= nl2br(e($report['reason'])) ?></blockquote>
                    <?php endif; ?>

                    <?php if ($report['scan_verdict']): $v = verdictInfo($report['scan_verdict']); ?>
                        <p class="small text-muted mb-0">
                            BaitCheck verdict at the time:
                            <span class="badge text-bg-<?= $v['color'] ?>"><?= $v['short'] ?></span> (score <?= (int) $report['scan_score'] ?>)
                            <a href="../result.php?id=<?= (int) $report['scan_id'] ?>" target="_blank" rel="noopener" class="link-arrow">View scan <i class="bi bi-arrow-up-right"></i></a>
                        </p>
                    <?php endif; ?>
                </div>
            </div>

            <?php if ($report['status'] === 'pending'): ?>
                <div class="report-actions">
                    <form method="POST" class="d-flex flex-wrap align-items-end gap-2 m-0">
                        <?= csrfField() ?>
                        <input type="hidden" name="report_id" value="<?= (int) $report['id'] ?>">
                        <input type="hidden" name="action" value="confirm">
                        <input type="hidden" name="return_status" value="<?= e($statusFilter) ?>">
                        <input type="hidden" name="return_type" value="<?= e($typeFilter) ?>">
                        <?php if ($registrable !== $domain): ?>
                            <div>
                                <label class="form-label small text-muted mb-1" for="scope<?= (int) $report['id'] ?>">Add to the <?= $listName ?></label>
                                <select name="scope" id="scope<?= (int) $report['id'] ?>" class="form-select form-select-sm">
                                    <option value="host">Only <?= e($domain) ?></option>
                                    <option value="domain"><?= e($registrable) ?> and all its subdomains</option>
                                </select>
                            </div>
                        <?php endif; ?>
                        <button class="btn btn-sm btn-confirm"
                                data-confirm="Confirm this report and add it to the <?= $listName ?>?">
                            <i class="bi bi-check-lg"></i> Confirm and add to <?= $listName ?>
                        </button>
                    </form>
                    <form method="POST" class="m-0">
                        <?= csrfField() ?>
                        <input type="hidden" name="report_id" value="<?= (int) $report['id'] ?>">
                        <input type="hidden" name="action" value="reject">
                        <input type="hidden" name="return_status" value="<?= e($statusFilter) ?>">
                        <input type="hidden" name="return_type" value="<?= e($typeFilter) ?>">
                        <button class="btn btn-sm btn-outline-secondary"><i class="bi bi-x-lg"></i> Reject</button>
                    </form>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endforeach; ?>

<?php require '../includes/footer.php'; ?>
