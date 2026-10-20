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

$pageTitle = 'Reports | PhishGuard Admin';
$activePage = 'reports';
require '../includes/admin_header.php';
?>

<h1 class="h3 fw-bold mb-4">User Reports</h1>

<form class="row g-2 mb-4" method="GET">
    <div class="col-6 col-md-3">
        <select name="status" class="form-select" aria-label="Filter by status">
            <?php foreach (['pending' => 'Pending', 'confirmed' => 'Confirmed', 'rejected' => 'Rejected', 'all' => 'All statuses'] as $key => $label): ?>
                <option value="<?= $key ?>" <?= $statusFilter === $key ? 'selected' : '' ?>><?= $label ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <div class="col-6 col-md-3">
        <select name="type" class="form-select" aria-label="Filter by type">
            <option value="all">All types</option>
            <?php foreach ($typeInfo as $key => $info): ?>
                <option value="<?= $key ?>" <?= $typeFilter === $key ? 'selected' : '' ?>><?= $info['label'] ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <div class="col-md-2 d-grid">
        <button class="btn btn-accent"><i class="bi bi-funnel"></i> Filter</button>
    </div>
</form>

<?php if (!$reports): ?>
    <div class="alert alert-light border text-center py-5">
        <i class="bi bi-inbox display-6 d-block mb-2 text-muted"></i>
        <?= $statusFilter === 'pending' ? 'No reports are waiting for review.' : 'No reports match these filters.' ?>
    </div>
<?php endif; ?>

<?php foreach ($reports as $report):
    $type = $typeInfo[$report['type']];
    $domain = $report['domain'];
    $registrable = Detector::registrableDomain($domain);
    $listName = $report['type'] === 'phishing' ? 'blacklist' : 'trusted list'; ?>
    <div class="card border-0 shadow-sm mb-3 report-card">
        <div class="card-body p-4">
            <div class="d-flex flex-wrap justify-content-between gap-2 mb-2">
                <div class="d-flex flex-wrap gap-2 align-items-center">
                    <span class="badge text-bg-<?= $type['color'] ?>"><i class="bi <?= $type['icon'] ?>"></i> <?= $type['label'] ?></span>
                    <span class="badge text-bg-<?= $statusColors[$report['status']] ?>"><?= ucfirst($report['status']) ?></span>
                    <span class="text-muted small">#<?= (int) $report['id'] ?> &middot; <?= timeAgo((int) $report['age']) ?></span>
                </div>
                <?php if ($report['status'] === 'pending' && $report['similar'] > 1): ?>
                    <span class="small text-muted"><i class="bi bi-people"></i> <?= (int) $report['similar'] ?> pending reports for this domain</span>
                <?php endif; ?>
            </div>

            <p class="font-monospace text-break mb-2"><?= e($report['url']) ?></p>

            <?php if ($report['reason']): ?>
                <blockquote class="report-reason small mb-2"><?= nl2br(e($report['reason'])) ?></blockquote>
            <?php endif; ?>

            <?php if ($report['scan_verdict']): $v = verdictInfo($report['scan_verdict']); ?>
                <p class="small text-muted mb-0">
                    PhishGuard verdict at the time:
                    <span class="badge text-bg-<?= $v['color'] ?>"><?= $v['short'] ?></span> (score <?= (int) $report['scan_score'] ?>)
                    <a href="../result.php?id=<?= (int) $report['scan_id'] ?>" target="_blank" rel="noopener">View scan</a>
                </p>
            <?php endif; ?>

            <?php if ($report['status'] === 'pending'): ?>
                <hr>
                <div class="d-flex flex-wrap align-items-end justify-content-between gap-3">
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
                        <button class="btn btn-sm btn-<?= $type['color'] ?>"
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
