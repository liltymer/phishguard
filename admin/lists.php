<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

requireAdmin();

$pdo = db();

$lists = [
    'blacklist' => ['label' => 'Blacklist', 'icon' => 'bi-slash-circle', 'color' => 'danger',
                    'help' => 'Any URL on these domains is marked as phishing with a score of 100.'],
    'whitelist' => ['label' => 'Trusted list', 'icon' => 'bi-patch-check', 'color' => 'success',
                    'help' => 'URLs on these domains are trusted and score 0. Add only official, well-known websites.'],
];

$list = $_GET['list'] ?? $_POST['list'] ?? 'blacklist';
if (!isset($lists[$list])) {
    $list = 'blacklist';
}
$other = $list === 'blacklist' ? 'whitelist' : 'blacklist';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        setFlash('danger', 'Your session expired. Please try again.');
    } elseif (($_POST['action'] ?? '') === 'add') {
        $domain = cleanDomain($_POST['domain'] ?? '');
        $note = mb_substr(trim($_POST['note'] ?? ''), 0, 255);

        $inOther = $pdo->prepare("SELECT 1 FROM $other WHERE domain = ?");
        $inOther->execute([$domain]);

        if ($domain === null) {
            setFlash('danger', 'Please enter a valid domain name, for example evil-site.com.');
        } elseif ($inOther->fetchColumn()) {
            setFlash('danger', "\"$domain\" is on the {$lists[$other]['label']}. Remove it there first.");
        } else {
            $insert = $pdo->prepare("INSERT INTO $list (domain, note) VALUES (?, ?) ON CONFLICT (domain) DO NOTHING");
            $insert->execute([$domain, $note !== '' ? $note : null]);
            $insert->rowCount()
                ? setFlash('success', "\"$domain\" added to the {$lists[$list]['label']}.")
                : setFlash('warning', "\"$domain\" is already on the {$lists[$list]['label']}.");
        }
    } elseif (($_POST['action'] ?? '') === 'remove') {
        $stmt = $pdo->prepare("SELECT domain FROM $list WHERE id = ?");
        $stmt->execute([(int) ($_POST['id'] ?? 0)]);
        $domain = $stmt->fetchColumn();

        if ($domain !== false) {
            $pdo->prepare("DELETE FROM $list WHERE id = ?")->execute([(int) $_POST['id']]);
            setFlash('success', "\"$domain\" removed from the {$lists[$list]['label']}.");
        }
    }

    header('Location: lists.php?list=' . $list);
    exit;
}

$counts = [];
foreach (array_keys($lists) as $key) {
    $counts[$key] = (int) $pdo->query("SELECT COUNT(*) FROM $key")->fetchColumn();
}

$search = trim($_GET['q'] ?? '');
$stmt = $pdo->prepare("SELECT id, domain, note, to_char(added_at, 'FMDD Mon YYYY') AS added FROM $list WHERE domain ILIKE ? ORDER BY added_at DESC, id DESC LIMIT 500");
$stmt->execute(['%' . addcslashes($search, '%_\\') . '%']);
$entries = $stmt->fetchAll();

$current = $lists[$list];
$pageTitle = $current['label'] . ' | BaitCheck Admin';
$activePage = 'lists';
require '../includes/admin_header.php';
?>

<?php $listTone = $list === 'blacklist' ? 'phishing' : 'safe'; ?>

<div class="page-head reveal">
    <div>
        <span class="section-eyebrow">Admin</span>
        <h1 class="page-title">Domain lists</h1>
        <p class="text-soft mb-0">Domains here override the detection engine for every scan.</p>
    </div>
</div>

<nav class="seg-tabs mb-4 reveal" style="--d: 80ms" aria-label="Choose a list">
    <?php foreach ($lists as $key => $info): ?>
        <a href="lists.php?list=<?= $key ?>" class="<?= $key === $list ? 'active' : '' ?>" <?= $key === $list ? 'aria-current="page"' : '' ?>>
            <i class="bi <?= $info['icon'] ?>"></i> <?= $info['label'] ?> <span class="seg-count"><?= $counts[$key] ?></span>
        </a>
    <?php endforeach; ?>
</nav>

<div class="row g-4">
    <div class="col-lg-4 reveal" style="--d: 140ms">
        <div class="card verdict-<?= $listTone ?>">
            <div class="card-body p-4">
                <div class="d-flex align-items-center gap-3 mb-3">
                    <span class="url-avatar"><i class="bi <?= $current['icon'] ?>"></i></span>
                    <h2 class="h6 fw-bold mb-0">Add to the <?= $current['label'] ?></h2>
                </div>
                <p class="small text-muted"><?= $current['help'] ?></p>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="add">
                    <input type="hidden" name="list" value="<?= $list ?>">
                    <div class="mb-3">
                        <label for="domain" class="form-label small fw-semibold">Domain</label>
                        <div class="field-icon">
                            <i class="bi bi-globe2" aria-hidden="true"></i>
                            <input type="text" name="domain" id="domain" class="form-control" required maxlength="253"
                                   placeholder="<?= $list === 'blacklist' ? 'fake-bank-login.com' : 'mybank.com.gh' ?>"
                                   spellcheck="false" autocapitalize="off">
                        </div>
                        <div class="form-text">You can paste a full URL; only the domain is kept.</div>
                    </div>
                    <div class="mb-3">
                        <label for="note" class="form-label small fw-semibold">Note <span class="text-muted fw-normal">(optional)</span></label>
                        <input type="text" name="note" id="note" class="form-control" maxlength="255"
                               placeholder="Where this came from">
                    </div>
                    <button class="btn btn-accent w-100"><i class="bi bi-plus-lg"></i> Add domain</button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-lg-8 reveal" style="--d: 200ms">
        <form class="mb-3" method="GET" role="search">
            <input type="hidden" name="list" value="<?= $list ?>">
            <div class="search-bar">
                <i class="bi bi-search" aria-hidden="true"></i>
                <label for="listSearch" class="visually-hidden">Search domains</label>
                <input type="search" name="q" id="listSearch" class="form-control" placeholder="Search domains..."
                       value="<?= e($search) ?>" spellcheck="false" autocapitalize="off" data-shortcut="/">
                <kbd class="d-none d-md-inline-block" title="Press / to search">/</kbd>
                <button class="btn btn-accent btn-sm">Search</button>
            </div>
        </form>

        <?php if (!$entries): ?>
            <div class="card text-center">
                <div class="card-body py-5">
                    <span class="icon-chip icon-chip-lg mx-auto"><i class="bi <?= $search !== '' ? 'bi-search' : $current['icon'] ?>"></i></span>
                    <h2 class="h6 fw-bold mt-2"><?= $search !== '' ? 'No domains match your search' : 'This list is empty' ?></h2>
                    <p class="small text-muted mb-0"><?= $search !== '' ? 'Try a shorter search.' : 'Add a domain with the form, or confirm a user report.' ?></p>
                </div>
            </div>
        <?php else: ?>
            <div class="card">
                <ul class="domain-list list-unstyled mb-0">
                    <?php foreach ($entries as $n => $entry): ?>
                        <li class="row-in verdict-<?= $listTone ?>" style="--d: <?= 200 + min($n, 12) * 40 ?>ms">
                            <span class="url-avatar"><i class="bi <?= $current['icon'] ?>"></i></span>
                            <div class="min-w-0 flex-grow-1">
                                <div class="font-monospace fw-semibold text-truncate"><?= highlight($entry['domain'], $search) ?></div>
                                <div class="small text-muted text-truncate">
                                    Added <?= e($entry['added']) ?><?php if ($entry['note']): ?> &middot; <?= e($entry['note']) ?><?php endif; ?>
                                </div>
                            </div>
                            <form method="POST" class="m-0">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="remove">
                                <input type="hidden" name="list" value="<?= $list ?>">
                                <input type="hidden" name="id" value="<?= (int) $entry['id'] ?>">
                                <button class="btn btn-sm btn-icon btn-icon-danger" aria-label="Remove <?= e($entry['domain']) ?>"
                                        data-confirm="Remove <?= e($entry['domain']) ?> from the <?= $current['label'] ?>?">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </form>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php require '../includes/footer.php'; ?>
