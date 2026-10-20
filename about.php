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

$pageTitle = 'How It Works | PhishGuard';
$pageDescription = 'How PhishGuard checks links for phishing: the ' . count(Detector::RULES) . ' checks, the risk score and how to stay safe.';
$activePage = 'about';
require 'includes/header.php';
?>

<section class="hero text-light py-5">
    <div class="container py-lg-3 text-center">
        <h1 class="display-6 fw-bold mb-3">How PhishGuard works</h1>
        <p class="lead text-light-50 mb-0 mx-auto about-lead">
            PhishGuard inspects a link for the tricks scammers use, without ever opening the website,
            so checking a dangerous link is always safe.
        </p>
    </div>
</section>

<section class="container py-5">
    <div class="row g-4 text-center">
        <?php
        $steps = [
            ['bi-clipboard-check', 'Paste a link', 'Copy a link from an SMS, email or WhatsApp message and paste it into the scanner.'],
            ['bi-cpu', 'We run ' . count(Detector::RULES) . ' checks', 'Each warning sign adds points to a risk score. The link itself is never visited.'],
            ['bi-clipboard-data', 'Get a clear verdict', 'You see the score, the real website behind the link and exactly why it was flagged.'],
        ];
        foreach ($steps as $i => [$icon, $title, $text]): ?>
            <div class="col-md-4">
                <div class="step-number"><?= $i + 1 ?></div>
                <i class="bi <?= $icon ?> feature-icon d-block mb-2"></i>
                <h2 class="h6 fw-bold"><?= $title ?></h2>
                <p class="small text-muted mb-0"><?= $text ?></p>
            </div>
        <?php endforeach; ?>
    </div>
</section>

<section class="bg-white py-5">
    <div class="container">
        <h2 class="h4 fw-bold text-center mb-2">The risk score</h2>
        <p class="text-muted text-center mb-4">Points from every check are added together, up to a maximum of 100.</p>
        <div class="row g-3 justify-content-center">
            <?php
            $bands = [
                ['safe', '0 to ' . (Detector::SUSPICIOUS_AT - 1)],
                ['suspicious', Detector::SUSPICIOUS_AT . ' to ' . (Detector::PHISHING_AT - 1)],
                ['phishing', Detector::PHISHING_AT . ' to 100'],
            ];
            foreach ($bands as [$key, $range]): $info = verdictInfo($key); ?>
                <div class="col-md-4">
                    <div class="card stat-card stat-<?= $info['color'] ?> h-100">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <span class="fw-bold text-<?= $info['color'] ?>"><i class="bi <?= $info['icon'] ?>"></i> <?= $info['label'] ?></span>
                                <span class="badge text-bg-light border"><?= $range ?></span>
                            </div>
                            <p class="small text-muted mb-0"><?= $info['text'] ?></p>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<section class="container py-5">
    <h2 class="h4 fw-bold text-center mb-2">What we check</h2>
    <p class="text-muted text-center mb-4">
        Websites on our trusted list (such as google.com) score 0 and skip these checks.
    </p>
    <div class="row g-4">
        <?php foreach ($groups as $group => $rules): ?>
            <div class="col-lg-6">
                <div class="card border-0 shadow-sm h-100 rules-card">
                    <div class="card-body p-4">
                        <h3 class="h6 fw-bold mb-3"><i class="bi <?= $groupIcons[$group] ?? 'bi-check2-square' ?> text-accent-dark"></i> <?= e($group) ?></h3>
                        <div class="table-responsive">
                            <table class="table table-sm align-middle mb-0 rules-table">
                                <thead><tr><th>Check</th><th>Example</th><th class="text-end">Points</th></tr></thead>
                                <tbody>
                                    <?php foreach ($rules as $rule): ?>
                                        <tr>
                                            <td><?= e($rule['label']) ?></td>
                                            <td class="font-monospace small text-muted"><?= e($rule['example']) ?></td>
                                            <td class="text-end text-nowrap fw-semibold">+<?= e($rule['points']) ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</section>

<section class="bg-white py-5">
    <div class="container">
        <div class="row g-4 g-lg-5">
            <div class="col-lg-6">
                <h2 class="h4 fw-bold mb-3"><i class="bi bi-people text-accent-dark"></i> It learns from users</h2>
                <ol class="mb-0">
                    <li class="mb-2">Anyone can <a href="report.php">report a link</a> that PhishGuard missed, or a genuine site it flagged by mistake.</li>
                    <li class="mb-2">An administrator reviews each report.</li>
                    <li>Confirmed phishing domains go on the <strong>blacklist</strong> and score 100 for everyone.
                        Confirmed genuine sites go on the <strong>trusted list</strong>.</li>
                </ol>
            </div>
            <div class="col-lg-6">
                <h2 class="h4 fw-bold mb-3"><i class="bi bi-shield-check text-accent-dark"></i> How to stay safe</h2>
                <ul class="mb-0">
                    <li class="mb-2">Never share your PIN, password or MoMo code, whoever asks.</li>
                    <li class="mb-2">Be wary of urgent messages: "your account will be blocked today".</li>
                    <li class="mb-2">Type your bank's address yourself instead of tapping a link.</li>
                    <li>Look at the real domain: in <code>mtn.com.verify-now.xyz</code> it is <code>verify-now.xyz</code>.</li>
                </ul>
            </div>
        </div>
    </div>
</section>

<section class="container py-5">
    <div class="alert alert-light border mb-4">
        <h2 class="h6 fw-bold"><i class="bi bi-info-circle"></i> Limitations</h2>
        <p class="small mb-0">
            PhishGuard looks for warning signs in the link itself. It does not open the website or read its content,
            so a brand-new phishing site on an ordinary-looking domain may score low, and a genuine site can sometimes
            be flagged. Treat a <strong>Safe</strong> result as "no warning signs found", not a guarantee, and
            always think before entering personal details.
        </p>
    </div>
    <div class="text-center">
        <a href="index.php" class="btn btn-accent btn-lg px-4"><i class="bi bi-search"></i> Scan a link now</a>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
