<?php
// Small helpers shared by several pages

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

// Must be called before any HTML is sent
function startSession(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start([
            'cookie_httponly' => true,
            'cookie_samesite' => 'Lax',
        ]);
    }
}

// CSRF protection: every form carries a secret token that other websites cannot read
function csrfToken(): string
{
    startSession();

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function csrfField(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '">';
}

function verifyCsrf(?string $token): bool
{
    startSession();

    return is_string($token) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// One-time message shown on the next page, e.g. after a redirect
function setFlash(string $type, string $message): void
{
    startSession();
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function flashMessage(): string
{
    startSession();

    if (empty($_SESSION['flash'])) {
        return '';
    }

    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    $icon = $flash['type'] === 'success' ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill';

    return '<div class="alert alert-' . e($flash['type']) . ' d-flex gap-2" role="alert">'
        . '<i class="bi ' . $icon . '"></i><div>' . e($flash['message']) . '</div></div>';
}

/**
 * Turn admin input such as "https://www.Evil.com/login" into "www.evil.com".
 * Returns null when the input is not a valid domain name or IP address.
 */
function cleanDomain(string $input): ?string
{
    $value = strtolower(trim($input));

    if (!preg_match('#^[a-z][a-z0-9+.-]*://#', $value)) {
        $value = 'http://' . $value;
    }

    $host = parse_url($value, PHP_URL_HOST);
    if (!is_string($host)) {
        return null;
    }

    $host = rtrim($host, '.');
    $isDomain = preg_match('/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $host);

    return ($isDomain || filter_var($host, FILTER_VALIDATE_IP)) ? $host : null;
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
