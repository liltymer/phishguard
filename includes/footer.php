<?php $base = $base ?? ''; ?>
</main>
<footer class="bg-navy text-light py-4 mt-5">
    <div class="container d-flex flex-column flex-md-row justify-content-between align-items-center gap-2 small">
        <span>&copy; <?= date('Y') ?> PhishGuard. Phishing URL Detection System.</span>
        <a href="<?= $base ?>admin/index.php" class="footer-link"><i class="bi bi-person-lock"></i> Admin</a>
    </div>
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="<?= $base ?>assets/js/main.js"></script>
</body>
</html>
