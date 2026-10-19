<?php
$pageTitle = 'PhishGuard — Phishing URL Detection';
require 'includes/header.php';
?>

<section class="hero text-light py-5">
    <div class="container py-lg-4">
        <div class="row justify-content-center text-center">
            <div class="col-lg-8">
                <h1 class="display-5 fw-bold mb-3">Is that link safe to click?</h1>
                <p class="lead mb-4 text-light-50">
                    Paste any URL and PhishGuard will analyse it for common phishing signs
                    before you open it.
                </p>

                <form id="scanForm" action="scan.php" method="POST" class="scan-form" novalidate>
                    <div class="input-group input-group-lg shadow">
                        <span class="input-group-text bg-white"><i class="bi bi-link-45deg"></i></span>
                        <input type="text" name="url" id="urlInput" class="form-control"
                               placeholder="https://example.com/login" autocomplete="off" required>
                        <button class="btn btn-accent px-4" type="submit">
                            <i class="bi bi-search"></i> Scan
                        </button>
                    </div>
                    <div id="urlError" class="text-warning small mt-2 text-start <?= isset($_GET['error']) ? '' : 'd-none' ?>">
                        <?= isset($_GET['error']) ? 'That does not look like a valid web address. Please check it and try again.' : '' ?>
                    </div>
                </form>
            </div>
        </div>
    </div>
</section>

<section class="container py-5">
    <h2 class="h4 fw-bold text-center mb-4">What we check</h2>
    <div class="row g-4">
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body">
                    <i class="bi bi-globe2 feature-icon"></i>
                    <h3 class="h6 fw-bold mt-3">Domain tricks</h3>
                    <p class="small text-muted mb-0">IP addresses instead of names, lookalike domains
                        such as <code>paypa1.com</code>, and too many subdomains.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body">
                    <i class="bi bi-braces feature-icon"></i>
                    <h3 class="h6 fw-bold mt-3">URL structure</h3>
                    <p class="small text-muted mb-0">Very long URLs, hidden <code>@</code> symbols,
                        missing HTTPS and link shorteners that hide the real destination.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card feature-card h-100">
                <div class="card-body">
                    <i class="bi bi-database-check feature-icon"></i>
                    <h3 class="h6 fw-bold mt-3">Known threats</h3>
                    <p class="small text-muted mb-0">Suspicious keywords like "verify" or "login",
                        and matches against our blacklist of reported phishing domains.</p>
                </div>
            </div>
        </div>
    </div>
</section>

<?php require 'includes/footer.php'; ?>
