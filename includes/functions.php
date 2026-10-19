<?php
// Small helpers shared by several pages

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

// Label, Bootstrap colour, icon and advice for each verdict
function verdictInfo(string $verdict): array
{
    $verdicts = [
        'safe' => [
            'label' => 'Looks Safe', 'short' => 'Safe', 'color' => 'success', 'icon' => 'bi-shield-check',
            'text'  => 'We found no strong signs of phishing. Still be careful before entering passwords or payment details.',
        ],
        'suspicious' => [
            'label' => 'Suspicious', 'short' => 'Suspicious', 'color' => 'warning', 'icon' => 'bi-exclamation-triangle',
            'text'  => 'This link has some warning signs. Do not enter personal information unless you are sure it is genuine.',
        ],
        'phishing' => [
            'label' => 'Likely Phishing', 'short' => 'Phishing', 'color' => 'danger', 'icon' => 'bi-shield-x',
            'text'  => 'This link shows strong signs of phishing. Do not open it or enter any information.',
        ],
    ];

    return $verdicts[$verdict] ?? $verdicts['suspicious'];
}

// How serious a single reason is, based on its points
function severity(int $points): array
{
    if ($points >= 30) {
        return ['label' => 'High', 'color' => 'danger'];
    }
    if ($points >= 15) {
        return ['label' => 'Medium', 'color' => 'warning'];
    }
    if ($points > 0) {
        return ['label' => 'Low', 'color' => 'secondary'];
    }
    return ['label' => 'Info', 'color' => 'success'];
}

// Takes an age in seconds (worked out by MySQL so PHP and MySQL time zones can't disagree)
function timeAgo(int $seconds): string
{
    if ($seconds < 60) {
        return 'just now';
    }

    foreach (['day' => 86400, 'hour' => 3600, 'minute' => 60] as $unit => $size) {
        if ($seconds >= $size) {
            $n = intdiv($seconds, $size);
            return $n . ' ' . $unit . ($n > 1 ? 's' : '') . ' ago';
        }
    }

    return 'just now';
}
