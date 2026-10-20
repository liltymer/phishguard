<?php
require 'config/db.php';
require 'includes/functions.php';
require 'includes/Detector.php';

startSession();

const MAX_REPORTS_PER_HOUR = 5;
const MAX_REASON_LENGTH = 500;

$types = [
    'phishing'       => 'This link is phishing (BaitCheck missed it)',
    'false_positive' => 'This is a genuine website (false alarm)',
];

$pdo = db();
$errors = [];

// Values shown in the form: from the submitted form, or prefilled from a result page link
$form = [
    'url'     => trim($_POST['url'] ?? $_GET['url'] ?? ''),
    'type'    => $_POST['type'] ?? $_GET['type'] ?? 'phishing',
    'reason'  => trim($_POST['reason'] ?? ''),
    'scan_id' => (int) ($_POST['scan_id'] ?? $_GET['scan'] ?? 0),
];
if (!isset($types[$form['type']])) {
    $form['type'] = 'phishing';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;

    // Hidden field that people never see; bots that fill in every field get a fake success
    if (!empty($_POST['website'])) {
        header('Location: report.php?status=sent');
        exit;
    }

    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Your session expired. Please submit the form again.';
    }

    $url = Detector::normalize($form['url']);
    if ($form['url'] === '') {
        $errors[] = 'Please enter the URL you want to report.';
    } elseif ($url === null || strlen($url) > 2000) {
        $errors[] = 'That does not look like a valid web address.';
    }

    if (mb_strlen($form['reason']) > MAX_REASON_LENGTH) {
        $errors[] = 'Please keep the details under ' . MAX_REASON_LENGTH . ' characters.';
    }

    if (!$errors) {
        $recent = $pdo->prepare("SELECT COUNT(*) FROM reports WHERE ip_address = ? AND created_at > now() - INTERVAL '1 hour'");
        $recent->execute([$ip]);
        if ($recent->fetchColumn() >= MAX_REPORTS_PER_HOUR) {
            $errors[] = 'You have sent several reports recently. Please wait a while before sending another.';
        }
    }

    if (!$errors) {
        $duplicate = $pdo->prepare("SELECT id FROM reports WHERE url = ? AND type = ? AND status = 'pending' LIMIT 1");
        $duplicate->execute([$url, $form['type']]);

        if ($duplicate->fetch()) {
            header('Location: report.php?status=duplicate');
            exit;
        }

        // Only link the report to a scan if that scan really is for this URL
        $scanId = null;
        if ($form['scan_id'] > 0) {
            $scan = $pdo->prepare('SELECT id FROM scans WHERE id = ? AND url = ?');
            $scan->execute([$form['scan_id'], $url]);
            $scanId = $scan->fetchColumn() ?: null;
        }

        $insert = $pdo->prepare(
            'INSERT INTO reports (url, domain, type, reason, scan_id, ip_address) VALUES (?, ?, ?, ?, ?, ?)'
        );
        $insert->execute([
            $url,
            strtolower(parse_url($url, PHP_URL_HOST)),
            $form['type'],
            $form['reason'] !== '' ? $form['reason'] : null,
            $scanId,
            $ip,
        ]);

        // Post/Redirect/Get: refreshing the page will not submit the report twice
        header('Location: report.php?status=sent');
        exit;
    }
}

$status = $_GET['status'] ?? '';

$pageTitle = 'Report a URL | BaitCheck';
$activePage = 'report';
require 'includes/header.php';
?>

<section class="container page-section">
    <div class="page-head reveal">
        <div>
            <span class="section-eyebrow">Report</span>
            <h1 class="page-title">Report a link</h1>
            <p class="text-soft mb-0 page-lead">
                Help us improve BaitCheck. Reports are reviewed by an administrator, and confirmed
                phishing links are added to our blacklist so other people are protected.
            </p>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-lg-7">
            <?php if ($status === 'sent'): ?>
                <div class="notice notice-success mb-4 reveal" role="alert">
                    <span class="notice-icon"><i class="bi bi-check-lg"></i></span>
                    <div><strong>Thank you, your report has been received.</strong><br>An administrator will review it shortly.</div>
                </div>
            <?php elseif ($status === 'duplicate'): ?>
                <div class="notice notice-info mb-4 reveal" role="alert">
                    <span class="notice-icon"><i class="bi bi-info-lg"></i></span>
                    <div><strong>This link has already been reported</strong> and is waiting for review. Thank you for checking.</div>
                </div>
            <?php endif; ?>

            <?php if ($errors): ?>
                <div class="notice notice-error mb-4" role="alert">
                    <span class="notice-icon"><i class="bi bi-exclamation-lg"></i></span>
                    <ul class="mb-0 ps-3">
                        <?php foreach ($errors as $error): ?>
                            <li><?= e($error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <div class="card reveal" style="--d: 80ms">
                <div class="card-body p-4 p-md-5">
                    <form method="POST" action="report.php" id="reportForm" novalidate>
                        <?= csrfField() ?>
                        <input type="hidden" name="scan_id" value="<?= $form['scan_id'] ?: '' ?>">

                        <div class="hp-field" aria-hidden="true">
                            <label for="website">Leave this field empty</label>
                            <input type="text" name="website" id="website" tabindex="-1" autocomplete="off">
                        </div>

                        <div class="mb-4">
                            <label for="url" class="form-label fw-semibold">Link</label>
                            <div class="field-icon">
                                <i class="bi bi-link-45deg" aria-hidden="true"></i>
                                <input type="text" name="url" id="url" class="form-control form-control-lg" required maxlength="2000"
                                       placeholder="https://example.com/login" value="<?= e($form['url']) ?>"
                                       spellcheck="false" autocapitalize="off">
                            </div>
                        </div>

                        <fieldset class="mb-4">
                            <legend class="form-label fw-semibold fs-6">What are you reporting?</legend>
                            <div class="row g-3">
                                <?php
                                $tiles = [
                                    'phishing'       => ['bi-shield-x', 'phishing', 'A phishing link', 'BaitCheck missed it, or it is not on our blacklist yet.'],
                                    'false_positive' => ['bi-shield-check', 'safe', 'A false alarm', 'This is a genuine website that BaitCheck flagged.'],
                                ];
                                foreach ($tiles as $key => [$icon, $tone, $title, $text]): ?>
                                    <div class="col-sm-6">
                                        <input class="tile-input visually-hidden" type="radio" name="type" id="type_<?= $key ?>"
                                               value="<?= $key ?>" <?= $form['type'] === $key ? 'checked' : '' ?>>
                                        <label class="choice-tile verdict-<?= $tone ?>" for="type_<?= $key ?>">
                                            <span class="choice-check" aria-hidden="true"><i class="bi bi-check-lg"></i></span>
                                            <span class="url-avatar mb-2"><i class="bi <?= $icon ?>"></i></span>
                                            <span class="d-block fw-bold"><?= $title ?></span>
                                            <span class="d-block small text-muted"><?= $text ?></span>
                                        </label>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </fieldset>

                        <div class="mb-4">
                            <label for="reason" class="form-label fw-semibold">
                                Details <span class="text-muted fw-normal">(optional)</span>
                            </label>
                            <textarea name="reason" id="reason" class="form-control" rows="4"
                                      maxlength="<?= MAX_REASON_LENGTH ?>"
                                      placeholder="For example: I received this link in an SMS claiming to be from my bank."><?= e($form['reason']) ?></textarea>
                            <div class="form-text text-end"><span id="reasonCount"><?= mb_strlen($form['reason']) ?></span> / <?= MAX_REASON_LENGTH ?></div>
                        </div>

                        <button type="submit" class="btn btn-accent btn-lg px-4"><i class="bi bi-send"></i> Submit report</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-lg-5">
            <div class="card mb-4 reveal" style="--d: 160ms">
                <div class="card-body p-4">
                    <h2 class="h6 fw-bold mb-4">What happens next</h2>
                    <ol class="timeline list-unstyled mb-0">
                        <li>
                            <strong>An administrator reviews your report</strong>
                            <span>Every report is checked by a person before anything changes.</span>
                        </li>
                        <li>
                            <strong>Confirmed phishing goes on the blacklist</strong>
                            <span>From then on the domain scores 100 for everyone who checks it.</span>
                        </li>
                        <li>
                            <strong>Confirmed false alarms are trusted</strong>
                            <span>The domain is added to the trusted list so it is not flagged again.</span>
                        </li>
                    </ol>
                </div>
            </div>
            <div class="card reveal" style="--d: 240ms">
                <div class="card-body p-4">
                    <h2 class="h6 fw-bold mb-3">Signs of a phishing message</h2>
                    <ul class="sign-list list-unstyled mb-0">
                        <li><span class="icon-chip"><i class="bi bi-alarm"></i></span> Urgent warnings such as "your account will be closed today".</li>
                        <li><span class="icon-chip"><i class="bi bi-key"></i></span> Requests for your PIN, password or MoMo code.</li>
                        <li><span class="icon-chip"><i class="bi bi-gift"></i></span> Prizes or rewards you never entered for.</li>
                        <li><span class="icon-chip"><i class="bi bi-link-45deg"></i></span> Links that do not match the company's official website.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
