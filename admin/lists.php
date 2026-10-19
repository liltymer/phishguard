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
            $insert = $pdo->prepare("INSERT IGNORE INTO $list (domain, note) VALUES (?, ?)");
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
$stmt = $pdo->prepare("SELECT id, domain, note, DATE_FORMAT(added_at, '%e %b %Y') AS added FROM $list WHERE domain LIKE ? ORDER BY added_at DESC, id DESC LIMIT 500");
$stmt->execute(['%' . addcslashes($search, '%_\\') . '%']);
$entries = $stmt->fetchAll();

$current = $lists[$list];
$pageTitle = $current['label'] . ' | PhishGuard Admin';
$activePage = 'lists';
require '../includes/admin_header.php';
?>

<h1 class="h3 fw-bold mb-4">Domain Lists</h1>

<ul class="nav nav-tabs mb-4">
    <?php foreach ($lists as $key => $info): ?>
        <li class="nav-item">
            <a class="nav-link <?= $key === $list ? 'active' : '' ?>" href="lists.php?list=<?= $key ?>"
                <?= $key === $list ? 'aria-current="page"' : '' ?>>
                <i class="bi <?= $info['icon'] ?> text-<?= $info['color'] ?>"></i> <?= $info['label'] ?>
                <span class="badge text-bg-light border ms-1"><?= $counts[$key] ?></span>
            </a>
        </li>
    <?php endforeach; ?>
</ul>

<div class="row g-4">
    <div class="col-lg-4">
        <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
                <h2 class="h6 fw-bold mb-2">Add to the <?= $current['label'] ?></h2>
                <p class="small text-muted"><?= $current['help'] ?></p>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="add">
                    <input type="hidden" name="list" value="<?= $list ?>">
                    <div class="mb-3">
                        <label for="domain" class="form-label small fw-semibold">Domain</label>
                        <input type="text" name="domain" id="domain" class="form-control" required maxlength="253"
                               placeholder="<?= $list === 'blacklist' ? 'fake-bank-login.com' : 'mybank.com.gh' ?>">
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

    <div class="col-lg-8">
        <form class="mb-3" method="GET">
            <input type="hidden" name="list" value="<?= $list ?>">
            <div class="input-group">
                <input type="search" name="q" class="form-control" placeholder="Search domains..." value="<?= e($search) ?>">
                <button class="btn btn-outline-secondary"><i class="bi bi-search"></i> Search</button>
            </div>
        </form>

        <?php if (!$entries): ?>
            <div class="alert alert-light border text-center py-4">
                <?= $search !== '' ? 'No domains match your search.' : 'This list is empty.' ?>
            </div>
        <?php else: ?>
            <div class="card border-0 shadow-sm">
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead class="table-light">
                            <tr><th>Domain</th><th class="d-none d-md-table-cell">Note</th><th class="d-none d-sm-table-cell">Added</th><th></th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($entries as $entry): ?>
                                <tr>
                                    <td class="font-monospace small"><?= e($entry['domain']) ?></td>
                                    <td class="d-none d-md-table-cell small text-muted"><?= e($entry['note']) ?></td>
                                    <td class="d-none d-sm-table-cell small text-muted text-nowrap"><?= e($entry['added']) ?></td>
                                    <td class="text-end">
                                        <form method="POST" class="m-0">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="remove">
                                            <input type="hidden" name="list" value="<?= $list ?>">
                                            <input type="hidden" name="id" value="<?= (int) $entry['id'] ?>">
                                            <button class="btn btn-sm btn-outline-danger" aria-label="Remove <?= e($entry['domain']) ?>"
                                                    data-confirm="Remove <?= e($entry['domain']) ?> from the <?= $current['label'] ?>?">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php require '../includes/footer.php'; ?>
