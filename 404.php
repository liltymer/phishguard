<?php
// Shown by Apache for any missing page (see .htaccess). Links are absolute because
// this page can be shown for a URL in any folder.
http_response_code(404);

require __DIR__ . '/includes/functions.php';

$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/') . '/';
$pageTitle = 'Page Not Found | PhishGuard';
require __DIR__ . '/includes/header.php';
?>

<section class="container py-5 text-center">
    <div class="py-lg-5">
        <i class="bi bi-signpost-split display-1 text-accent-dark"></i>
        <h1 class="h3 fw-bold mt-3">Page not found</h1>
        <p class="text-muted mb-4">The page you are looking for does not exist or has been moved.</p>
        <a href="<?= e($base) ?>index.php" class="btn btn-accent px-4"><i class="bi bi-house"></i> Back to the scanner</a>
    </div>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
