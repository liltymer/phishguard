<?php
// The three-step "how it works" row, shared by the home page and the How It Works page.
$steps = [
    ['bi-clipboard-check', 'Paste a link', 'Copy a link from an SMS, email or WhatsApp message and paste it into the scanner.'],
    ['bi-cpu', 'We run ' . count(Detector::RULES) . ' checks', 'Each warning sign adds points to a risk score. The link itself is never visited.'],
    ['bi-clipboard-data', 'Get a clear verdict', 'You see the score, the real website behind the link and exactly why it was flagged.'],
];
?>
<div class="row g-4 text-center steps">
    <?php foreach ($steps as $i => [$icon, $title, $text]): ?>
        <div class="col-md-4 step reveal" style="--d: <?= $i * 140 ?>ms">
            <span class="icon-chip icon-chip-lg"><i class="bi <?= $icon ?>"></i></span>
            <div class="step-label">Step <?= $i + 1 ?></div>
            <h3 class="h6 fw-bold"><?= $title ?></h3>
            <p class="small text-muted mb-0"><?= $text ?></p>
        </div>
    <?php endforeach; ?>
</div>
