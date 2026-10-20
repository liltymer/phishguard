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

// Keep the current filters when building links (page 1 and "all" are the defaults, so they are left out)
function pageLink(array $changes): string
{
    global $verdict, $search;

    $query = array_merge(['verdict' => $verdict, 'q' => $search], $changes);
    $query = array_filter($query, fn($v) => $v !== '' && $v !== 'all' && $v !== 1);

    return 'history.php' . ($query ? '?' . http_build_query($query) : '');
}

$pageTitle = 'Scan History | BaitCheck';
$activePage = 'history';
require 'includes/header.php';
?>

<section class="container page-section">
    <div class="page-head reveal">
        <div>
            <span class="section-eyebrow">History</span>
            <h1 class="page-title">Scan history</h1>
            <p class="text-soft mb-0">Every link checked with BaitCheck, newest first.</p>
        </div>
        <a href="index.php" class="btn btn-accent"><i class="bi bi-search"></i> Scan a link</a>
    </div>

    <!-- The summary cards double as verdict filters -->
    <nav class="row g-3 mb-4" aria-label="Filter by verdict">
        <?php
        $filters = ['all' => ['All scans', $totalScans, 'bi-collection', 'navy', null]];
        foreach ($totals as $key => $n) {
            $info = verdictInfo($key);
            $filters[$key] = [$info['short'], $n, $info['icon'], $info['color'], $key];
        }
        $i = 0;
        foreach ($filters as $key => [$label, $n, $icon, $color, $verdictKey]):
            $active = $verdict === $key;
            $share = $totalScans ? round($n / $totalScans * 100) : 0; ?>
            <div class="col-6 col-lg-3 reveal" style="--d: <?= $i++ * 80 ?>ms">
                <a href="<?= e(pageLink(['verdict' => $key, 'page' => 1])) ?>"
                   class="card stat-card stat-filter stat-<?= $color ?> h-100 text-decoration-none <?= $verdictKey ? 'verdict-' . $verdictKey : '' ?> <?= $active ? 'active' : '' ?>"
                   <?= $active ? 'aria-current="true"' : '' ?>>
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <span class="stat-chip"><i class="bi <?= $icon ?>"></i></span>
                            <?php if ($active): ?>
                                <span class="filter-tag"><i class="bi bi-funnel-fill"></i> Showing</span>
                            <?php endif; ?>
                        </div>
                        <div class="stat-value" data-count="<?= (int) $n ?>"><?= $n ?></div>
                        <div class="d-flex justify-content-between align-items-baseline small">
                            <span class="text-muted"><?= $label ?></span>
                            <?php if ($verdictKey): ?><span class="text-muted"><?= $share ?>%</span><?php endif; ?>
                        </div>
                        <?php if ($verdictKey): ?>
                            <div class="share-bar" aria-hidden="true"><span style="width: <?= $share ?>%"></span></div>
                        <?php endif; ?>
                    </div>
                </a>
            </div>
        <?php endforeach; ?>
    </nav>

    <form class="mb-3 reveal" method="GET" role="search">
        <?php if ($verdict !== 'all'): ?>
            <input type="hidden" name="verdict" value="<?= e($verdict) ?>">
        <?php endif; ?>
        <div class="search-bar">
            <i class="bi bi-search" aria-hidden="true"></i>
            <label for="historySearch" class="visually-hidden">Search URLs</label>
            <input type="search" name="q" id="historySearch" class="form-control" placeholder="Search URLs, e.g. paypal"
                   value="<?= e($search) ?>" spellcheck="false" autocapitalize="off" data-shortcut="/">
            <kbd class="d-none d-md-inline-block" title="Press / to search">/</kbd>
            <button class="btn btn-accent btn-sm">Search</button>
        </div>
    </form>

    <?php if ($verdict !== 'all' || $search !== ''): ?>
        <div class="filter-summary small mb-3">
            <span><strong><?= $matching ?></strong> result<?= $matching === 1 ? '' : 's' ?></span>
            <?php if ($verdict !== 'all'): ?>
                <a href="<?= e(pageLink(['verdict' => 'all', 'page' => 1])) ?>" class="filter-pill"><?= verdictInfo($verdict)['short'] ?> <i class="bi bi-x"></i></a>
            <?php endif; ?>
            <?php if ($search !== ''): ?>
                <a href="<?= e(pageLink(['q' => '', 'page' => 1])) ?>" class="filter-pill">&ldquo;<?= e($search) ?>&rdquo; <i class="bi bi-x"></i></a>
            <?php endif; ?>
            <a href="history.php" class="ms-1">Clear all</a>
        </div>
    <?php endif; ?>

    <?php if (!$scans): ?>
        <div class="card text-center reveal">
            <div class="card-body py-5">
                <?php if ($totalScans): ?>
                    <span class="icon-chip icon-chip-lg mx-auto"><i class="bi bi-search"></i></span>
                    <h2 class="h5 fw-bold mt-2">No scans match your filters</h2>
                    <p class="text-muted mb-4">Try a different search, or show every verdict.</p>
                    <a href="history.php" class="btn btn-outline-secondary btn-sm">Clear filters</a>
                <?php else: ?>
                    <span class="icon-chip icon-chip-lg mx-auto"><i class="bi bi-hourglass-split"></i></span>
                    <h2 class="h5 fw-bold mt-2">No links checked yet</h2>
                    <p class="text-muted mb-4">Every link you scan will appear here.</p>
                    <a href="index.php" class="btn btn-accent btn-sm"><i class="bi bi-search"></i> Scan your first link</a>
                <?php endif; ?>
            </div>
        </div>
    <?php else: ?>
        <!-- Table on tablets and computers. Each row opens its result (main.js); the arrow button does the same. -->
        <div class="card history-card d-none d-md-block reveal">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead>
                        <tr>
                            <th>Link</th>
                            <th>Score</th>
                            <th>Verdict</th>
                            <th>Scanned</th>
                            <th><span class="visually-hidden">Details</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($scans as $n => $scan):
                            $info = verdictInfo($scan['verdict']);
                            $host = parse_url($scan['url'], PHP_URL_HOST) ?: $scan['url'];
                            $href = 'result.php?id=' . (int) $scan['id']; ?>
                            <tr class="row-link row-in verdict-<?= e($scan['verdict']) ?>" data-href="<?= $href ?>" style="--d: <?= 120 + $n * 45 ?>ms">
                                <td>
                                    <div class="d-flex align-items-center gap-3 url-cell">
                                        <span class="url-avatar"><i class="bi <?= $info['icon'] ?>"></i></span>
                                        <div class="min-w-0">
                                            <div class="url-host text-truncate"><?= highlight($host, $search) ?></div>
                                            <div class="url-full text-truncate" title="<?= e($scan['url']) ?>"><?= highlight($scan['url'], $search) ?></div>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <div class="d-flex align-items-center gap-2">
                                        <span class="fw-bold score-num text-verdict"><?= (int) $scan['score'] ?></span>
                                        <span class="score-mini" aria-hidden="true"><span style="width: <?= (int) $scan['score'] ?>%"></span></span>
                                    </div>
                                </td>
                                <td><span class="badge text-bg-<?= $info['color'] ?>"><?= $info['short'] ?></span></td>
                                <td class="text-muted small text-nowrap"><?= timeAgo((int) $scan['age']) ?></td>
                                <td class="text-end">
                                    <a href="<?= $href ?>" class="btn btn-sm btn-icon" aria-label="View result for <?= e($host) ?>">
                                        <i class="bi bi-arrow-right"></i>
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Cards on phones, where a table would be cramped -->
        <div class="list-group d-md-none">
            <?php foreach ($scans as $n => $scan):
                $info = verdictInfo($scan['verdict']);
                $host = parse_url($scan['url'], PHP_URL_HOST) ?: $scan['url']; ?>
                <a href="result.php?id=<?= (int) $scan['id'] ?>" class="list-group-item list-group-item-action py-3 row-in verdict-<?= e($scan['verdict']) ?>" style="--d: <?= 120 + $n * 45 ?>ms">
                    <div class="d-flex align-items-center gap-3 mb-2">
                        <span class="url-avatar"><i class="bi <?= $info['icon'] ?>"></i></span>
                        <div class="min-w-0 flex-grow-1">
                            <div class="url-host text-truncate"><?= highlight($host, $search) ?></div>
                            <div class="url-full text-break"><?= highlight($scan['url'], $search) ?></div>
                        </div>
                    </div>
                    <div class="d-flex align-items-center gap-2 small">
                        <span class="badge text-bg-<?= $info['color'] ?>"><?= $info['short'] ?></span>
                        <span class="fw-bold score-num text-verdict"><?= (int) $scan['score'] ?></span>
                        <span class="score-mini flex-grow-1" aria-hidden="true"><span style="width: <?= (int) $scan['score'] ?>%"></span></span>
                        <span class="text-muted text-nowrap ms-2"><?= timeAgo((int) $scan['age']) ?></span>
                    </div>
                </a>
            <?php endforeach; ?>
        </div>

        <div class="d-flex flex-wrap justify-content-between align-items-center mt-3 gap-2">
            <span class="text-muted small">
                Showing <?= $offset + 1 ?> to <?= $offset + count($scans) ?> of <?= $matching ?>
            </span>
            <?php if ($pages > 1): ?>
                <nav aria-label="Pages">
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
