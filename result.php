<?php
require 'config/db.php';
require 'includes/functions.php';
require 'includes/Detector.php';

$stmt = db()->prepare('SELECT *, EXTRACT(EPOCH FROM now() - created_at)::int AS age FROM scans WHERE id = ?');
$stmt->execute([(int) ($_GET['id'] ?? 0)]);
$scan = $stmt->fetch();

if (!$scan) {
    header('Location: index.php');
    exit;
}

$reasons = json_decode($scan['reasons'], true);
usort($reasons, fn($a, $b) => $b['points'] <=> $a['points']);
$warnings = array_filter($reasons, fn($r) => $r['points'] > 0);

$v = verdictInfo($scan['verdict']);
$parts = parse_url($scan['url']);
$host = $parts['host'];
$realDomain = Detector::registrableDomain(strtolower($host));
$isIp = (bool) filter_var(trim($host, '[]'), FILTER_VALIDATE_IP);

// Split the host so the real domain can be highlighted, e.g. paypal.com.[evil.xyz]
$prefix = substr($host, 0, strlen($host) - strlen($realDomain));

// Score bar: each warning sign is a segment. Points can add up past 100, where the score is capped.
$pointsTotal = array_sum(array_column($warnings, 'points'));
$barScale = max($pointsTotal, 100);

// Checks that found nothing. Blacklisted and trusted domains skip the other checks,
// and domain-name checks do not apply to an IP address.
$triggered = array_column($reasons, 'rule');
$listMatch = in_array('blacklist', $triggered, true) ? 'blacklist' : (in_array('whitelist', $triggered, true) ? 'whitelist' : null);
$notApplicable = $isIp ? ['typosquat', 'brand', 'subdomains', 'hyphens', 'tld'] : [];
$passed = array_diff_key(Detector::RULES, array_flip(array_merge($triggered, $notApplicable)));

// Other users may already have reported this domain as phishing
$pending = db()->prepare("SELECT COUNT(*) FROM reports WHERE domain = ? AND type = 'phishing' AND status = 'pending'");
$pending->execute([strtolower($host)]);
$pendingReports = (int) $pending->fetchColumn();

$reportLink = fn(string $type) => 'report.php?' . http_build_query(['url' => $scan['url'], 'type' => $type, 'scan' => $scan['id']]);

$pageTitle = 'Scan Result | BaitCheck';
require 'includes/header.php';
?>

<section class="container py-5 verdict-<?= e($scan['verdict']) ?>">
    <div class="row justify-content-center">
        <div class="col-lg-9">

            <div class="card result-card">
                <div class="card-body p-4 p-md-5">
                    <div class="row align-items-center g-4">
                        <div class="col-md-4 text-center">
                            <div class="gauge" data-score="<?= (int) $scan['score'] ?>">
                                <svg viewBox="0 0 120 120" aria-hidden="true">
                                    <circle class="gauge-track" cx="60" cy="60" r="52"></circle>
                                    <circle class="gauge-fill" cx="60" cy="60" r="52"></circle>
                                </svg>
                                <div class="gauge-label">
                                    <span class="gauge-value">0</span>
                                    <small>risk score</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-8 text-center text-md-start">
                            <h1 class="h3 fw-bold text-verdict">
                                <i class="bi <?= $v['icon'] ?>"></i> <?= $v['label'] ?>
                            </h1>
                            <p class="mb-3"><?= $v['text'] ?></p>
                            <p class="small text-muted mb-0">
                                <i class="bi bi-clock"></i> Scanned <?= timeAgo((int) $scan['age']) ?>
                                &middot; <?= count($warnings) ?> warning sign<?= count($warnings) === 1 ? '' : 's' ?> found
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <?php if ($pendingReports > 0): ?>
                <div class="alert alert-warning d-flex gap-2 mt-4 mb-0" role="alert">
                    <i class="bi bi-people-fill"></i>
                    <div>
                        This domain has been reported as phishing by other users
                        (<?= $pendingReports ?> report<?= $pendingReports > 1 ? 's' : '' ?>) and is under review.
                    </div>
                </div>
            <?php endif; ?>

            <div class="card advice-card mt-4">
                <div class="card-body p-4">
                    <h2 class="h6 fw-bold mb-3"><i class="bi bi-signpost-2 text-verdict"></i> What to do now</h2>
                    <ul class="advice-list mb-0">
                        <?php foreach ($v['advice'] as $tip): ?>
                            <li><?= e($tip) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>

            <div class="card mt-4">
                <div class="card-body p-4">
                    <h2 class="h6 fw-bold mb-3"><i class="bi bi-diagram-3"></i> URL breakdown</h2>
                    <p class="url-display text-break mb-3">
                        <span class="text-muted"><?= e($parts['scheme']) ?>://</span><?php if (isset($parts['user'])): ?><span class="url-part-trick"><?= e($parts['user']) ?>@</span><?php endif; ?><span class="text-muted"><?= e($prefix) ?></span><span class="url-part-domain"><?= e($realDomain) ?></span><?php if (isset($parts['port'])): ?><span>:<?= (int) $parts['port'] ?></span><?php endif; ?><span class="text-muted"><?= e(($parts['path'] ?? '') . (isset($parts['query']) ? '?' . $parts['query'] : '')) ?></span>
                    </p>
                    <dl class="row small mb-0">
                        <dt class="col-sm-3">Real website</dt>
                        <dd class="col-sm-9"><span class="url-part-domain"><?= e($realDomain) ?></span>
                            <span class="text-muted">(the website you would actually connect to)</span></dd>
                        <dt class="col-sm-3">Connection</dt>
                        <dd class="col-sm-9">
                            <?php if ($parts['scheme'] === 'https'): ?>
                                <i class="bi bi-lock-fill text-success"></i> Encrypted (HTTPS)
                            <?php else: ?>
                                <i class="bi bi-unlock-fill text-danger"></i> Not encrypted (HTTP)
                            <?php endif; ?>
                        </dd>
                        <?php if ($prefix !== '' && $prefix !== 'www.'): ?>
                            <dt class="col-sm-3">Subdomains</dt>
                            <dd class="col-sm-9"><code><?= e(rtrim($prefix, '.')) ?></code></dd>
                        <?php endif; ?>
                        <?php if (!empty($parts['path']) && $parts['path'] !== '/'): ?>
                            <dt class="col-sm-3">Path</dt>
                            <dd class="col-sm-9 text-break"><code><?= e($parts['path']) ?></code></dd>
                        <?php endif; ?>
                    </dl>
                    <div class="share-safe mt-3 pt-3 d-sm-flex align-items-center justify-content-between gap-3">
                        <p class="small text-muted mb-2 mb-sm-0">
                            <strong class="text-body">Warning someone about this link?</strong>
                            Copy a safe version that can't be opened by accident:
                            <code class="d-block text-break mt-1"><?= e(defang($scan['url'])) ?></code>
                        </p>
                        <button type="button" class="btn btn-sm btn-outline-secondary flex-shrink-0" data-copy="<?= e(defang($scan['url'])) ?>">
                            <i class="bi bi-copy"></i> <span>Copy safe link</span>
                        </button>
                    </div>
                </div>
            </div>

            <h2 class="h5 fw-bold mt-5 mb-3">Why we gave this result</h2>

            <div class="score-scale mb-4" role="img"
                 aria-label="Risk score <?= (int) $scan['score'] ?> out of 100, in the <?= e($v['short']) ?> range">
                <div class="score-track">
                    <div class="score-fill">
                        <?php foreach ($warnings as $reason): $s = severity($reason['points']); ?>
                            <span class="score-seg seg-<?= $s['color'] ?>" style="width: <?= round($reason['points'] / $barScale * 100, 2) ?>%"
                                  title="<?= e('+' . $reason['points'] . ': ' . $reason['message']) ?>"></span>
                        <?php endforeach; ?>
                    </div>
                </div>
                <div class="score-zones small">
                    <span style="width: <?= Detector::SUSPICIOUS_AT ?>%">Safe</span>
                    <span style="width: <?= Detector::PHISHING_AT - Detector::SUSPICIOUS_AT ?>%">Suspicious <?= Detector::SUSPICIOUS_AT ?></span>
                    <span style="width: <?= 100 - Detector::PHISHING_AT ?>%">Phishing <?= Detector::PHISHING_AT ?></span>
                </div>
                <?php if ($pointsTotal > 100): ?>
                    <p class="small text-muted mt-2 mb-0">
                        The warning signs add up to <?= $pointsTotal ?> points. The score is capped at 100.
                    </p>
                <?php endif; ?>
            </div>

            <?php if (!$reasons): ?>
                <div class="alert alert-light border">
                    <i class="bi bi-check-circle text-success"></i> None of our phishing checks were triggered.
                </div>
            <?php else: ?>
                <ul class="list-group shadow-sm">
                    <?php foreach ($reasons as $reason): $s = severity($reason['points']); ?>
                        <li class="list-group-item d-flex align-items-start gap-3 py-3">
                            <span class="badge text-bg-<?= $s['color'] ?> severity-badge"><?= $s['label'] ?></span>
                            <span class="flex-grow-1"><?= e($reason['message']) ?></span>
                            <?php if ($reason['points'] > 0): ?>
                                <span class="text-muted small fw-semibold">+<?= (int) $reason['points'] ?></span>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <?php if ($listMatch === 'blacklist'): ?>
                <p class="small text-muted mt-3 mb-0"><i class="bi bi-info-circle"></i>
                    This domain was confirmed as phishing by an administrator, so no other checks were needed.</p>
            <?php elseif ($listMatch === 'whitelist'): ?>
                <p class="small text-muted mt-3 mb-0"><i class="bi bi-info-circle"></i>
                    Trusted websites skip the other checks.</p>
            <?php elseif ($passed): ?>
                <details class="checks-passed card mt-3">
                    <summary class="card-body py-3">
                        <i class="bi bi-check-circle-fill text-success"></i>
                        <strong><?= count($passed) ?> other check<?= count($passed) === 1 ? '' : 's' ?></strong> found nothing wrong
                        <span class="text-muted small">(show)</span>
                    </summary>
                    <ul class="checks-grid list-unstyled small px-3 pb-3 mb-0">
                        <?php foreach ($passed as $rule): ?>
                            <li><i class="bi bi-check2 text-success"></i> <span class="text-muted">No sign of:</span> <?= e($rule['label']) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </details>
            <?php endif; ?>

            <div class="card card-muted mt-4">
                <div class="card-body p-4 d-md-flex align-items-center justify-content-between gap-3">
                    <div class="mb-3 mb-md-0">
                        <h2 class="h6 fw-bold mb-1">Think this result is wrong?</h2>
                        <p class="small text-muted mb-0">Your report helps us improve detection for everyone.</p>
                    </div>
                    <div class="d-flex flex-wrap gap-2 flex-shrink-0">
                        <?php if ($scan['verdict'] !== 'phishing'): ?>
                            <a href="<?= e($reportLink('phishing')) ?>" class="btn btn-sm btn-outline-danger">
                                <i class="bi bi-flag"></i> Report as phishing
                            </a>
                        <?php endif; ?>
                        <?php if ($scan['verdict'] !== 'safe'): ?>
                            <a href="<?= e($reportLink('false_positive')) ?>" class="btn btn-sm btn-outline-success">
                                <i class="bi bi-hand-thumbs-up"></i> Report a false alarm
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="d-flex flex-wrap justify-content-center gap-2 mt-4">
                <a href="index.php" class="btn btn-accent px-4"><i class="bi bi-arrow-repeat"></i> Scan another URL</a>
                <a href="history.php" class="btn btn-outline-secondary px-4"><i class="bi bi-clock-history"></i> View history</a>
            </div>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
