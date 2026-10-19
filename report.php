<?php
require 'config/db.php';
require 'includes/functions.php';
require 'includes/Detector.php';

startSession();

const MAX_REPORTS_PER_HOUR = 5;
const MAX_REASON_LENGTH = 500;

$types = [
    'phishing'       => 'This link is phishing (PhishGuard missed it)',
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
        $recent = $pdo->prepare('SELECT COUNT(*) FROM reports WHERE ip_address = ? AND created_at > NOW() - INTERVAL 1 HOUR');
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

$pageTitle = 'Report a URL | PhishGuard';
$activePage = 'report';
require 'includes/header.php';
?>

<section class="container py-5">
    <div class="row g-4 justify-content-center">
        <div class="col-lg-7">
            <h1 class="h3 fw-bold mb-2"><i class="bi bi-flag"></i> Report a URL</h1>
            <p class="text-muted mb-4">
                Help us improve PhishGuard. Reports are reviewed by an administrator, and confirmed
                phishing links are added to our blacklist so other users are protected.
            </p>

            <?php if ($status === 'sent'): ?>
                <div class="alert alert-success d-flex gap-2" role="alert">
                    <i class="bi bi-check-circle-fill"></i>
                    <div><strong>Thank you, your report has been received.</strong> An administrator will review it shortly.</div>
                </div>
            <?php elseif ($status === 'duplicate'): ?>
                <div class="alert alert-info d-flex gap-2" role="alert">
                    <i class="bi bi-info-circle-fill"></i>
                    <div><strong>This URL has already been reported</strong> and is waiting for review. Thank you for checking.</div>
                </div>
            <?php endif; ?>

            <?php if ($errors): ?>
                <div class="alert alert-danger" role="alert">
                    <ul class="mb-0 ps-3">
                        <?php foreach ($errors as $error): ?>
                            <li><?= e($error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <div class="card border-0 shadow-sm">
                <div class="card-body p-4">
                    <form method="POST" action="report.php" id="reportForm" novalidate>
                        <?= csrfField() ?>
                        <input type="hidden" name="scan_id" value="<?= $form['scan_id'] ?: '' ?>">

                        <div class="hp-field" aria-hidden="true">
                            <label for="website">Leave this field empty</label>
                            <input type="text" name="website" id="website" tabindex="-1" autocomplete="off">
                        </div>

                        <div class="mb-3">
                            <label for="url" class="form-label fw-semibold">URL</label>
                            <input type="text" name="url" id="url" class="form-control" required maxlength="2000"
                                   placeholder="https://example.com/login" value="<?= e($form['url']) ?>">
                        </div>

                        <fieldset class="mb-3">
                            <legend class="form-label fw-semibold fs-6">What are you reporting?</legend>
                            <?php foreach ($types as $key => $label): ?>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="type" id="type_<?= $key ?>"
                                           value="<?= $key ?>" <?= $form['type'] === $key ? 'checked' : '' ?>>
                                    <label class="form-check-label" for="type_<?= $key ?>"><?= e($label) ?></label>
                                </div>
                            <?php endforeach; ?>
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

                        <button type="submit" class="btn btn-accent px-4"><i class="bi bi-send"></i> Submit report</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="card border-0 shadow-sm mb-4">
                <div class="card-body p-4">
                    <h2 class="h6 fw-bold mb-3"><i class="bi bi-list-check"></i> What happens next</h2>
                    <ol class="small ps-3 mb-0">
                        <li class="mb-2">An administrator reviews your report.</li>
                        <li class="mb-2">If a phishing report is confirmed, the domain is added to the blacklist.</li>
                        <li>If a false alarm is confirmed, the domain is added to the trusted list.</li>
                    </ol>
                </div>
            </div>
            <div class="card border-0 shadow-sm">
                <div class="card-body p-4">
                    <h2 class="h6 fw-bold mb-3"><i class="bi bi-lightbulb"></i> Signs of a phishing message</h2>
                    <ul class="small ps-3 mb-0">
                        <li class="mb-2">Urgent warnings such as "your account will be closed today".</li>
                        <li class="mb-2">Requests for your PIN, password or MoMo code.</li>
                        <li class="mb-2">Prizes or rewards you never entered for.</li>
                        <li>Links that do not match the official website of the company.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
