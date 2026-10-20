<?php
require 'config/db.php';
require 'includes/functions.php';
require 'includes/Detector.php';

// Group the engine's rules for display: everything here comes from Detector, so it cannot drift.
// Groups are ordered so cards of similar length sit side by side.
$groups = array_fill_keys(['Domain tricks', 'URL structure', 'Wording', 'Known threats'], []);
foreach (Detector::RULES as $rule) {
    $groups[$rule['group']][] = $rule;
}
$groups = array_filter($groups);
$groupIcons = [
    'Known threats' => 'bi-database-x',
    'Domain tricks' => 'bi-globe2',
    'URL structure' => 'bi-braces',
    'Wording'       => 'bi-chat-left-text',
];

// Colour a rule's points like the result page does, using its highest value ("8 or 20" -> 20)
$ruleSeverity = function (string $points): array {
    preg_match_all('/\d+/', $points, $numbers);
    return severity((int) max($numbers[0] ?: [0]));
};

$pageTitle = 'How It Works | BaitCheck';
$pageDescription = 'How BaitCheck checks links for phishing: the ' . count(Detector::RULES) . ' checks, the risk score and how to stay safe.';
$activePage = 'about';
require 'includes/header.php';
?>

<section class="hero py-5">
    <div class="hero-glow" aria-hidden="true"></div>
    <div class="container py-lg-4 text-center position-relative">
        <span class="hero-eyebrow rise"><span class="pulse-dot"></span> <?= count(Detector::RULES) ?> checks, explained</span>
        <h1 class="hero-title hero-title-sm mt-4 mb-3 rise" style="--d: 80ms">How <span class="text-gradient text-shine">BaitCheck</span> works</h1>
        <p class="lead text-soft mb-0 mx-auto about-lead rise" style="--d: 160ms">
            BaitCheck inspects a link for the tricks scammers use, without ever opening the website,
            so checking a dangerous link is always safe.
        </p>
    </div>
</section>

<section class="container section-pad pt-4">
    <div class="section-head reveal">
        <span class="section-eyebrow">The process</span>
        <h2 class="section-title">Three steps, about one second</h2>
    </div>
    <?php require 'includes/steps.php'; ?>
</section>

<section class="container pb-5">
    <div class="section-head reveal">
        <span class="section-eyebrow">The risk score</span>
        <h2 class="section-title">Every warning sign adds points</h2>
        <p class="text-soft mt-2 mb-0">Points from every check are added together, up to a maximum of 100.</p>
    </div>

    <div class="score-legend reveal" aria-hidden="true">
        <div class="score-track score-track-lg">
            <div class="score-fill">
                <span class="score-seg" style="width: <?= Detector::SUSPICIOUS_AT ?>%; background: var(--v-safe)"></span>
                <span class="score-seg" style="width: <?= Detector::PHISHING_AT - Detector::SUSPICIOUS_AT ?>%; background: var(--v-suspicious)"></span>
                <span class="score-seg" style="width: <?= 100 - Detector::PHISHING_AT ?>%; background: var(--v-phishing)"></span>
            </div>
        </div>
        <div class="score-zones small">
            <span style="width: <?= Detector::SUSPICIOUS_AT ?>%">0</span>
            <span style="width: <?= Detector::PHISHING_AT - Detector::SUSPICIOUS_AT ?>%"><?= Detector::SUSPICIOUS_AT ?></span>
            <span class="d-flex justify-content-between" style="width: <?= 100 - Detector::PHISHING_AT ?>%"><?= Detector::PHISHING_AT ?> <span class="border-0 p-0">100</span></span>
        </div>
    </div>

    <div class="row g-3 mt-2">
        <?php
        $bands = [
            ['safe', '0 to ' . (Detector::SUSPICIOUS_AT - 1)],
            ['suspicious', Detector::SUSPICIOUS_AT . ' to ' . (Detector::PHISHING_AT - 1)],
            ['phishing', Detector::PHISHING_AT . ' to 100'],
        ];
        foreach ($bands as $i => [$key, $range]): $info = verdictInfo($key); ?>
            <div class="col-md-4 reveal" style="--d: <?= $i * 100 ?>ms">
                <div class="card stat-card stat-<?= $info['color'] ?> verdict-<?= $key ?> h-100">
                    <div class="card-body p-4">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span class="stat-chip"><i class="bi <?= $info['icon'] ?>"></i></span>
                            <span class="badge text-bg-<?= $info['color'] ?>"><?= $range ?></span>
                        </div>
                        <h3 class="h5 fw-bold text-verdict mb-2"><?= $info['label'] ?></h3>
                        <p class="small text-muted mb-0"><?= $info['text'] ?></p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</section>

<section class="section-alt section-pad">
    <div class="container">
        <div class="section-head reveal">
            <span class="section-eyebrow">What we check</span>
            <h2 class="section-title">All <?= count(Detector::RULES) ?> checks</h2>
            <p class="text-soft mt-2 mb-0">Websites on our trusted list (such as google.com) score 0 and skip these checks.</p>
        </div>
        <div class="row g-4">
            <?php $i = 0; foreach ($groups as $group => $rules): ?>
                <div class="col-lg-6 reveal" style="--d: <?= ($i++ % 2) * 100 ?>ms">
                    <div class="card h-100 rules-card">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-center gap-3 mb-3">
                                <span class="icon-chip"><i class="bi <?= $groupIcons[$group] ?? 'bi-check2-square' ?>"></i></span>
                                <div>
                                    <h3 class="h6 fw-bold mb-0"><?= e($group) ?></h3>
                                    <span class="small text-muted"><?= count($rules) ?> check<?= count($rules) === 1 ? '' : 's' ?></span>
                                </div>
                            </div>
                            <ul class="rule-list list-unstyled mb-0">
                                <?php foreach ($rules as $rule): $s = $ruleSeverity($rule['points']); ?>
                                    <li class="rule-row">
                                        <div class="min-w-0">
                                            <div class="rule-label"><?= e($rule['label']) ?></div>
                                            <code class="rule-example"><?= e($rule['example']) ?></code>
                                        </div>
                                        <span class="badge text-bg-<?= $s['color'] ?> points-badge">+<?= e($rule['points']) ?></span>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<section class="container section-pad">
    <div class="row g-4">
        <div class="col-lg-6 reveal">
            <div class="card h-100">
                <div class="card-body p-4 p-md-5">
                    <span class="section-eyebrow">Community</span>
                    <h2 class="h4 fw-bold mb-4">It learns from users</h2>
                    <ol class="timeline list-unstyled mb-0">
                        <li>
                            <strong>Anyone can report a link</strong>
                            <span><a href="report.php">Report a link</a> that BaitCheck missed, or a genuine site it flagged by mistake.</span>
                        </li>
                        <li>
                            <strong>An administrator reviews it</strong>
                            <span>Nothing changes until a person has checked the report.</span>
                        </li>
                        <li>
                            <strong>Everyone is protected</strong>
                            <span>Confirmed phishing domains go on the blacklist and score 100.
                                Confirmed genuine sites go on the trusted list.</span>
                        </li>
                    </ol>
                </div>
            </div>
        </div>
        <div class="col-lg-6 reveal" style="--d: 100ms">
            <div class="card h-100">
                <div class="card-body p-4 p-md-5">
                    <span class="section-eyebrow">Stay safe</span>
                    <h2 class="h4 fw-bold mb-4">How to stay safe</h2>
                    <ul class="sign-list list-unstyled mb-0">
                        <li><span class="icon-chip"><i class="bi bi-key"></i></span> Never share your PIN, password or MoMo code, whoever asks.</li>
                        <li><span class="icon-chip"><i class="bi bi-alarm"></i></span> Be wary of urgent messages: "your account will be blocked today".</li>
                        <li><span class="icon-chip"><i class="bi bi-keyboard"></i></span> Type your bank's address yourself instead of tapping a link.</li>
                        <li><span class="icon-chip"><i class="bi bi-search"></i></span>
                            <span>Look at the real domain: in <code>mtn.com.verify-now.xyz</code> it is <code>verify-now.xyz</code>.</span></li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <div class="notice notice-info mt-4 reveal" role="note">
        <span class="notice-icon"><i class="bi bi-info-lg"></i></span>
        <div>
            <strong>Limitations</strong>
            <p class="small mb-0 mt-1">
                BaitCheck looks for warning signs in the link itself. It does not open the website or read its content,
                so a brand-new phishing site on an ordinary-looking domain may score low, and a genuine site can sometimes
                be flagged. Treat a <strong>Safe</strong> result as "no warning signs found", not a guarantee, and
                always think before entering personal details.
            </p>
        </div>
    </div>
</section>

<section class="container pb-4">
    <div class="cta-card reveal">
        <div class="hero-glow" aria-hidden="true"></div>
        <div class="position-relative text-center">
            <h2 class="section-title mb-2">Ready to check a link?</h2>
            <p class="text-soft mb-4">Paste it in and get a verdict in about a second.</p>
            <a href="index.php" class="btn btn-accent btn-lg px-4"><i class="bi bi-search"></i> Scan a link now</a>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
