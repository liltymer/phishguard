<?php
require 'config/db.php';
require 'includes/functions.php';
require 'includes/Detector.php';

$pdo = db();
$stats = $pdo->query("
    SELECT
        (SELECT COUNT(*) FROM scans)                            AS scans,
        (SELECT COUNT(*) FROM scans WHERE verdict = 'phishing') AS phishing,
        (SELECT COUNT(*) FROM blacklist)                        AS blacklist
")->fetch();

// Sample links for a quick demo, one per verdict
$examples = [
    ['https://www.google.com', 'Safe', 'success'],
    ['https://mtn-promo.com', 'Suspicious', 'warning'],
    ['http://paypa1.com/signin', 'Phishing', 'danger'],
];

// The hero preview card shows real engine results for the example links (nothing is saved)
$detector = new Detector(
    $pdo->query('SELECT domain FROM blacklist')->fetchAll(PDO::FETCH_COLUMN),
    $pdo->query('SELECT domain FROM whitelist')->fetchAll(PDO::FETCH_COLUMN)
);
$demos = [];
foreach (array_reverse($examples) as [$url]) {
    $result = $detector->analyze($url);
    $warnings = array_values(array_filter($result['reasons'], fn($r) => $r['points'] > 0));
    usort($warnings, fn($a, $b) => $b['points'] <=> $a['points']);
    $demos[] = [
        'url'     => $url,
        'score'   => $result['score'],
        'verdict' => $result['verdict'],
        'label'   => verdictInfo($result['verdict'])['label'],
        'icon'    => verdictInfo($result['verdict'])['icon'],
        'reasons' => array_map(fn($r) => ['text' => $r['message'], 'level' => severity($r['points'])['label'], 'color' => severity($r['points'])['color'], 'points' => $r['points']], array_slice($warnings, 0, 2)),
    ];
}
$first = $demos[0];

$pageTitle = 'BaitCheck | Check a Link for Phishing';
$activePage = 'scan';
require 'includes/header.php';
?>

<section class="hero hero-home">
    <div class="hero-glow" aria-hidden="true"></div>
    <div class="container position-relative">
        <div class="row align-items-center g-5">
            <div class="col-lg-7 text-center text-lg-start">
                <span class="hero-eyebrow rise" style="--d: 0ms"><span class="pulse-dot"></span> <?= count(Detector::RULES) ?> checks &middot; instant &middot; the link is never opened</span>
                <h1 class="hero-title mt-4 mb-3 rise" style="--d: 80ms">Don't take<br class="d-none d-lg-inline"> the <span class="text-gradient text-shine">bait.</span></h1>
                <p class="lead hero-lead mb-4 text-soft rise" style="--d: 160ms">
                    Got a link in an SMS, email or WhatsApp message? Paste it below and BaitCheck will look
                    for phishing tricks without ever opening it.
                </p>

                <form id="scanForm" action="scan.php" method="POST" class="scan-form rise" style="--d: 240ms" novalidate>
                    <div class="input-group input-group-lg scan-box">
                        <span class="input-group-text d-none d-sm-flex"><i class="bi bi-link-45deg"></i></span>
                        <label for="urlInput" class="visually-hidden">URL to scan</label>
                        <input type="text" name="url" id="urlInput" class="form-control"
                               placeholder="Paste a link, e.g. https://example.com/login" autocomplete="off"
                               spellcheck="false" autocapitalize="off" required
                               data-typing="<?= e(json_encode(['paypa1.com/signin', 'bit.ly/3xYz12', 'mtn-promo.com', 'http://paypal.com@198.51.100.7'])) ?>">
                        <button type="button" class="btn btn-input d-none" id="clearUrl" aria-label="Clear the link">
                            <i class="bi bi-x-circle-fill"></i>
                        </button>
                        <button type="button" class="btn btn-input d-none" id="pasteUrl" aria-label="Paste from clipboard">
                            <i class="bi bi-clipboard"></i><span class="d-none d-sm-inline ms-1">Paste</span>
                        </button>
                        <button class="btn btn-accent px-3 px-sm-4" type="submit" id="scanButton">
                            <i class="bi bi-search"></i> Scan
                        </button>
                    </div>
                    <div id="urlError" class="text-warning small mt-2 text-start <?= isset($_GET['error']) ? '' : 'd-none' ?>" role="alert">
                        <?= isset($_GET['error']) ? 'That does not look like a valid web address. Please check it and try again.' : '' ?>
                    </div>
                </form>

                <div class="mt-3 small text-soft rise" style="--d: 320ms">
                    Try an example:
                    <?php foreach ($examples as [$url, $label, $color]): ?>
                        <button type="button" class="btn btn-sm btn-example ms-1" data-example="<?= e($url) ?>">
                            <span class="dot bg-<?= $color ?>"></span> <?= $label ?>
                        </button>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Live preview: cycles through real results for the example links (main.js) -->
            <div class="col-lg-5 d-none d-lg-block">
                <div class="preview-wrap rise" style="--d: 300ms">
                    <div class="card preview-card verdict-<?= e($first['verdict']) ?>" id="previewCard"
                         data-demos="<?= e(json_encode($demos)) ?>" aria-hidden="true">
                        <div class="preview-bar">
                            <span></span><span></span><span></span>
                            <small class="ms-auto text-muted">Live preview</small>
                        </div>
                        <div class="card-body p-4">
                            <div class="preview-url font-monospace small mb-4"><i class="bi bi-link-45deg"></i> <span data-field="url"><?= e($first['url']) ?></span></div>
                            <div class="d-flex align-items-center gap-4 mb-4">
                                <div class="mini-gauge" style="--score: <?= (int) $first['score'] ?>">
                                    <span data-field="score"><?= (int) $first['score'] ?></span>
                                </div>
                                <div>
                                    <div class="small text-muted mb-1">Verdict</div>
                                    <div class="h4 fw-bold mb-0 text-verdict"><i class="bi <?= e($first['icon']) ?>" data-field="icon"></i> <span data-field="label"><?= e($first['label']) ?></span></div>
                                </div>
                            </div>
                            <ul class="preview-reasons list-unstyled mb-0" data-field="reasons">
                                <?php foreach ($first['reasons'] as $r): ?>
                                    <li><span class="badge text-bg-<?= $r['color'] ?>"><?= $r['level'] ?></span> <span><?= e($r['text']) ?></span></li>
                                <?php endforeach; ?>
                                <?php if (!$first['reasons']): ?>
                                    <li><span class="badge text-bg-success">Clear</span> <span>No warning signs found.</span></li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    </div>
                    <div class="preview-dots" id="previewDots">
                        <?php foreach ($demos as $i => $d): ?><span class="<?= $i === 0 ? 'active' : '' ?>"></span><?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Shown while the scan is sent: main.js steps through the checks so people can see the work being done -->
<div class="scan-overlay" id="scanOverlay" hidden
     data-checks="<?= e(json_encode(array_column(Detector::RULES, 'label'))) ?>">
    <div class="scan-panel card" role="status" aria-live="polite">
        <div class="card-body p-4 text-center">
            <div class="scan-radar mb-3" aria-hidden="true"><i class="bi bi-shield-fill-check"></i></div>
            <h2 class="h5 fw-bold mb-1">Checking your link</h2>
            <p class="scan-url font-monospace small text-muted text-truncate mb-3" id="scanUrl"></p>
            <div class="progress mb-2" role="presentation">
                <div class="progress-bar bg-accent" id="scanProgress"></div>
            </div>
            <p class="small mb-0"><span class="text-muted">Check <span id="scanCount">0</span> of <?= count(Detector::RULES) ?>:</span>
                <span id="scanCheck" class="fw-semibold"></span></p>
        </div>
    </div>
</div>

<section class="container">
    <div class="row g-3">
        <?php
        $strip = [
            [$stats['scans'], 'links scanned', 'bi-search'],
            [$stats['phishing'], 'phishing links caught', 'bi-shield-x'],
            [count(Detector::RULES), 'checks on every link', 'bi-list-check'],
        ];
        foreach ($strip as $i => [$value, $label, $icon]): ?>
            <div class="col-4 reveal" style="--d: <?= $i * 90 ?>ms">
                <div class="card stat-card text-center h-100">
                    <div class="card-body py-3 py-md-4">
                        <div class="stat-value" data-count="<?= (int) $value ?>"><?= number_format((int) $value) ?></div>
                        <div class="small text-muted"><i class="bi <?= $icon ?>"></i> <?= $label ?></div>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</section>

<section class="container section-pad">
    <div class="section-head reveal">
        <span class="section-eyebrow">How it works</span>
        <h2 class="section-title">Three steps, about one second</h2>
    </div>
    <?php require 'includes/steps.php'; ?>
</section>

<section class="container pb-5">
    <div class="section-head reveal">
        <span class="section-eyebrow">What we check</span>
        <h2 class="section-title">The tricks scammers rely on</h2>
    </div>
    <div class="row g-4">
        <?php
        $features = [
            ['bi-globe2', 'Domain tricks', 'IP addresses instead of names, lookalike domains such as <code>paypa1.com</code>, and too many subdomains.'],
            ['bi-braces', 'URL structure', 'Very long URLs, hidden <code>@</code> symbols, missing HTTPS and link shorteners that hide the real destination.'],
            ['bi-database-check', 'Known threats', 'Suspicious keywords like "verify" or "login", and matches against our blacklist of reported phishing domains.'],
        ];
        foreach ($features as $i => [$icon, $title, $text]): ?>
            <div class="col-md-4 reveal" style="--d: <?= $i * 100 ?>ms">
                <div class="card feature-card h-100">
                    <div class="card-body p-4">
                        <span class="icon-chip"><i class="bi <?= $icon ?>"></i></span>
                        <h3 class="h6 fw-bold mt-3"><?= $title ?></h3>
                        <p class="small text-muted mb-0"><?= $text ?></p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <p class="text-center mt-4 mb-0 reveal">
        <a href="about.php" class="link-arrow fw-semibold">See all <?= count(Detector::RULES) ?> checks and how scoring works <i class="bi bi-arrow-right"></i></a>
    </p>
</section>

<section class="container pb-4">
    <div class="cta-card reveal">
        <div class="hero-glow" aria-hidden="true"></div>
        <div class="position-relative text-center">
            <h2 class="section-title mb-2">Got a suspicious link right now?</h2>
            <p class="text-soft mb-4">Check it in seconds. It's free, and the link is never opened.</p>
            <a href="#urlInput" class="btn btn-accent btn-lg px-4" data-focus-scan><i class="bi bi-search"></i> Check a link</a>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
