<?php
require 'config/db.php';
require 'includes/functions.php';

const PER_PAGE = 15;

$pdo = db();

$verdict = $_GET['verdict'] ?? 'all';
if (!in_array($verdict, ['all', 'safe', 'suspicious', 'phishing'], true)) {
    $verdict = 'all';
}
$search = trim($_GET['q'] ?? '');
$page = max(1, (int) ($_GET['page'] ?? 1));

// Totals for the summary cards (all scans, ignoring filters)
$totals = ['safe' => 0, 'suspicious' => 0, 'phishing' => 0];
foreach ($pdo->query('SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict') as $row) {
    $totals[$row['verdict']] = (int) $row['n'];
}
$totalScans = array_sum($totals);

// Build the filtered query
$where = [];
$params = [];
if ($verdict !== 'all') {
    $where[] = 'verdict = ?';
    $params[] = $verdict;
}
if ($search !== '') {
    $where[] = 'url ILIKE ?';
    $params[] = '%' . addcslashes($search, '%_\\') . '%';
}
$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$count = $pdo->prepare("SELECT COUNT(*) FROM scans $whereSql");
$count->execute($params);
$matching = (int) $count->fetchColumn();

$pages = max(1, (int) ceil($matching / PER_PAGE));
$page = min($page, $pages);
$offset = ($page - 1) * PER_PAGE;

$stmt = $pdo->prepare("SELECT id, url, score, verdict, EXTRACT(EPOCH FROM now() - created_at)::int AS age FROM scans $whereSql
                       ORDER BY created_at DESC, id DESC LIMIT " . PER_PAGE . " OFFSET $offset");
$stmt->execute($params);
$scans = $stmt->fetchAll();

// Keep the current filters when building links
function pageLink(array $changes): string
{
    $query = array_merge(['verdict' => $_GET['verdict'] ?? 'all', 'q' => $_GET['q'] ?? ''], $changes);
    return 'history.php?' . http_build_query(array_filter($query, fn($v) => $v !== '' && $v !== 'all'));
}

$pageTitle = 'Scan History | PhishGuard';
$activePage = 'history';
require 'includes/header.php';
?>

<section class="container py-5">
    <h1 class="h3 fw-bold mb-4"><i class="bi bi-clock-history"></i> Scan History</h1>

    <div class="row g-3 mb-4">
        <div class="col-6 col-lg-3">
            <div class="card stat-card"><div class="card-body">
                <div class="stat-value"><?= $totalScans ?></div>
                <div class="text-muted small">Total scans</div>
            </div></div>
        </div>
        <?php foreach ($totals as $key => $n): $info = verdictInfo($key); ?>
            <div class="col-6 col-lg-3">
                <div class="card stat-card stat-<?= $info['color'] ?>"><div class="card-body">
                    <div class="stat-value text-<?= $info['color'] ?>"><?= $n ?></div>
                    <div class="text-muted small"><i class="bi <?= $info['icon'] ?>"></i> <?= $info['short'] ?></div>
                </div></div>
            </div>
        <?php endforeach; ?>
    </div>

    <form class="row g-2 mb-3" method="GET">
        <div class="col-md-6">
            <input type="search" name="q" class="form-control" placeholder="Search URLs..." value="<?= e($search) ?>">
        </div>
        <div class="col-8 col-md-4">
            <select name="verdict" class="form-select">
                <option value="all">All verdicts</option>
                <?php foreach (['safe', 'suspicious', 'phishing'] as $key): ?>
                    <option value="<?= $key ?>" <?= $verdict === $key ? 'selected' : '' ?>><?= verdictInfo($key)['short'] ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-4 col-md-2 d-grid">
            <button class="btn btn-accent"><i class="bi bi-funnel"></i> Filter</button>
        </div>
    </form>

    <?php if (!$scans): ?>
        <div class="alert alert-light border text-center py-5">
            <i class="bi bi-inbox display-6 d-block mb-2 text-muted"></i>
            <?= $totalScans ? 'No scans match your filters.' : 'No URLs have been scanned yet.' ?>
            <div class="mt-3"><a href="index.php" class="btn btn-accent btn-sm">Scan a URL</a></div>
        </div>
    <?php else: ?>
        <div class="card border-0 shadow-sm">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>URL</th>
                            <th class="text-center">Score</th>
                            <th>Verdict</th>
                            <th class="d-none d-md-table-cell">Scanned</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($scans as $scan): $info = verdictInfo($scan['verdict']); ?>
                            <tr>
                                <td class="history-url" title="<?= e($scan['url']) ?>"><?= e($scan['url']) ?></td>
                                <td class="text-center fw-semibold"><?= (int) $scan['score'] ?></td>
                                <td><span class="badge text-bg-<?= $info['color'] ?>"><?= $info['short'] ?></span></td>
                                <td class="d-none d-md-table-cell text-muted small"><?= timeAgo((int) $scan['age']) ?></td>
                                <td class="text-end">
                                    <a href="result.php?id=<?= (int) $scan['id'] ?>" class="btn btn-sm btn-outline-secondary">View</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="d-flex flex-wrap justify-content-between align-items-center mt-3 gap-2">
            <span class="text-muted small">
                Showing <?= $offset + 1 ?> to <?= $offset + count($scans) ?> of <?= $matching ?>
            </span>
            <?php if ($pages > 1): ?>
                <nav>
                    <ul class="pagination pagination-sm mb-0">
                        <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                            <a class="page-link" href="<?= e(pageLink(['page' => $page - 1])) ?>">Previous</a>
                        </li>
                        <?php for ($i = max(1, $page - 2); $i <= min($pages, $page + 2); $i++): ?>
                            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                <a class="page-link" href="<?= e(pageLink(['page' => $i])) ?>"><?= $i ?></a>
                            </li>
                        <?php endfor; ?>
                        <li class="page-item <?= $page >= $pages ? 'disabled' : '' ?>">
                            <a class="page-link" href="<?= e(pageLink(['page' => $page + 1])) ?>">Next</a>
                        </li>
                    </ul>
                </nav>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</section>

<?php require 'includes/footer.php'; ?>
