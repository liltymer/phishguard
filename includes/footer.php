<?php $base = $base ?? ''; ?>
</main>
<footer class="site-footer py-4 mt-5">
    <div class="container footer-inner small">
        <div class="footer-brand">
            <a href="<?= $base ?>index.php" class="brand text-decoration-none">
                <span class="brand-mark"><i class="bi bi-shield-fill-check"></i></span> <span>Bait<span class="text-gradient">Check</span></span>
            </a>
            <span class="footer-tagline">Don't take the bait.</span>
        </div>
        <div class="footer-meta">
            <span>&copy; <?= date('Y') ?> BaitCheck &middot; Phishing URL Detection System</span>
            <a href="<?= $base ?>admin/index.php" class="footer-link"><i class="bi bi-person-lock"></i> Admin</a>
        </div>
    </div>
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="<?= $base ?>assets/js/main.js"></script>
</body>
</html>
