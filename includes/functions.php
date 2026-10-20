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

// Label, Bootstrap colour, icon, summary and next steps for each verdict
function verdictInfo(string $verdict): array
{
    $verdicts = [
        'safe' => [
            'label' => 'Looks Safe', 'short' => 'Safe', 'color' => 'success', 'icon' => 'bi-shield-check',
            'text'  => 'We found no strong signs of phishing. Still be careful before entering passwords or payment details.',
            'advice' => [
                'Check the address bar shows the website you expect before you log in.',
                'Never share a PIN, password or one-time code (OTP), even on a genuine website.',
                'If the message was urgent or sounded too good to be true, be extra careful anyway.',
            ],
        ],
        'suspicious' => [
            'label' => 'Suspicious', 'short' => 'Suspicious', 'color' => 'warning', 'icon' => 'bi-exclamation-triangle',
            'text'  => 'This link has some warning signs. Do not enter personal information unless you are sure it is genuine.',
            'advice' => [
                'Do not open it from the message. Type the official website address yourself instead.',
                'Check with the company or person through a phone number or app you already trust.',
                'Never share a PIN, password or one-time code (OTP), whoever asks.',
            ],
        ],
        'phishing' => [
            'label' => 'Likely Phishing', 'short' => 'Phishing', 'color' => 'danger', 'icon' => 'bi-shield-x',
            'text'  => 'This link shows strong signs of phishing. Do not open it or enter any information.',
            'advice' => [
                'Do not open the link, and do not enter any passwords, PINs or card details.',
                'Delete the message, and block the sender if it came by SMS or WhatsApp.',
                'Already entered your details? Change that password now and call your bank or mobile money provider.',
                'If a friend sent it, warn them: their account may have been hacked.',
            ],
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

// Takes an age in seconds (worked out by the database so PHP and database time zones can't disagree)
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

/**
 * "Defang" a link so it cannot be opened by accident when shared in a warning:
 * http://paypal.com.evil.xyz/login -> hxxp://paypal[.]com[.]evil[.]xyz/login
 */
function defang(string $url): string
{
    [$scheme, $rest] = array_pad(explode('://', $url, 2), 2, '');
    $hostEnd = strcspn($rest, '/?#');

    return preg_replace('/^http/i', 'hxxp', $scheme) . '://'
        . str_replace('.', '[.]', substr($rest, 0, $hostEnd)) . substr($rest, $hostEnd);
}

// Escape $text for HTML and wrap every match of $term in <mark>
function highlight(string $text, string $term): string
{
    $parts = $term === '' ? false : preg_split('/(' . preg_quote($term, '/') . ')/iu', $text, -1, PREG_SPLIT_DELIM_CAPTURE);
    if ($parts === false) {
        return e($text);
    }

    $html = '';
    foreach ($parts as $i => $part) {
        $html .= $i % 2 ? '<mark>' . e($part) . '</mark>' : e($part);
    }

    return $html;
}
