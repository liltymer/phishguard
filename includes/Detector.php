<?php
/**
 * PhishGuard detection engine.
 *
 * Runs a set of rule-based checks on a URL. Each rule that matches adds
 * points to a risk score (0-100), and the score decides the verdict.
 */
class Detector
{
    // Score thresholds for each verdict
    const SUSPICIOUS_AT = 30;
    const PHISHING_AT   = 60;

    // Brands that phishers commonly impersonate
    const BRANDS = [
        'paypal', 'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix',
        'instagram', 'whatsapp', 'linkedin', 'yahoo', 'outlook', 'office365',
        'icloud', 'dropbox', 'twitter', 'telegram', 'binance', 'coinbase',
        'ecobank', 'stanbic', 'vodafone', 'absa', 'mtn', 'dhl', 'fedex',
    ];

    const SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
        'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink',
    ];

    const KEYWORDS = [
        'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'update',
        'secure', 'security', 'account', 'banking', 'confirm', 'password',
        'suspend', 'suspended', 'unlock', 'wallet', 'billing', 'invoice', 'webscr',
    ];

    // Cheap or free TLDs that are heavily abused for phishing
    const RISKY_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'zip', 'mov', 'click',
        'country', 'kim', 'work', 'support', 'rest', 'fit', 'icu', 'buzz',
    ];

    // Two-part public suffixes so "site.com.gh" is read as one domain
    const SECOND_LEVEL = [
        'com.gh', 'edu.gh', 'gov.gh', 'org.gh', 'co.uk', 'org.uk', 'ac.uk',
        'com.ng', 'co.za', 'com.au', 'co.in', 'com.br', 'co.ke',
    ];

    private array $blacklist;
    private array $whitelist;
    private array $reasons = [];
    private int $score = 0;

    public function __construct(array $blacklist = [], array $whitelist = [])
    {
        $this->blacklist = array_map('strtolower', $blacklist);
        $this->whitelist = array_map('strtolower', $whitelist);
    }

    /**
     * Normalise user input into a full URL, or return null if it is not a URL.
     * $hadScheme tells the caller whether the user typed http:// or https://.
     */
    public static function normalize(string $input, ?bool &$hadScheme = null): ?string
    {
        $url = trim($input);
        $hadScheme = (bool) preg_match('#^[a-z][a-z0-9+.-]*://#i', $url);

        if (!$hadScheme) {
            $url = 'http://' . $url;
        }

        $parts = parse_url($url);
        if ($parts === false || empty($parts['host']) || !in_array(strtolower($parts['scheme']), ['http', 'https'])) {
            return null;
        }

        $host = $parts['host'];
        if (!str_contains($host, '.') && !filter_var($host, FILTER_VALIDATE_IP)) {
            return null;
        }

        return $url;
    }

    /**
     * Analyse a normalised URL. Returns score, verdict, domain and reasons.
     */
    public function analyze(string $url, bool $hadScheme = true): array
    {
        $this->reasons = [];
        $this->score = 0;

        $parts  = parse_url($url);
        $host   = strtolower(rtrim($parts['host'], '.'));
        $scheme = strtolower($parts['scheme']);
        $path   = ($parts['path'] ?? '') . (isset($parts['query']) ? '?' . $parts['query'] : '');
        $domain = $this->registrableDomain($host);
        $isIp   = (bool) filter_var(trim($host, '[]'), FILTER_VALIDATE_IP);

        // Known lists come first: a blacklist match is final, a whitelist match is trusted
        if ($this->inList($host, $domain, $this->blacklist)) {
            $this->flag('blacklist', 'This domain is on the PhishGuard blacklist of known phishing sites.', 100);
            return $this->result($host);
        }

        if ($this->inList($host, $domain, $this->whitelist)) {
            return $this->result($host, 'This domain is on the list of trusted, well-known websites.');
        }

        if ($isIp) {
            $this->flag('ip_address', 'Uses an IP address instead of a domain name. Real companies almost never do this.', 45);
        }

        // parse_url puts anything before "@" in the user part, e.g. http://paypal.com@evil.com
        if (isset($parts['user'])) {
            $this->flag('at_symbol', 'Contains an "@" symbol. Browsers ignore everything before it, so the real site is "' . $host . '".', 30);
        }

        if ($hadScheme && $scheme !== 'https') {
            $this->flag('no_https', 'Does not use HTTPS, so the connection is not encrypted.', 10);
        }

        if (str_starts_with($host, 'xn--') || str_contains($host, '.xn--')) {
            $this->flag('punycode', 'Uses punycode (xn--), which can disguise lookalike characters from other alphabets.', 25);
        }

        if (!$isIp) {
            $this->checkBrand($host, $domain);
            $this->checkSubdomains($host, $domain);
            $this->checkHyphens($domain);
            $this->checkTld($domain);
        }

        if (in_array($domain, self::SHORTENERS, true)) {
            $this->flag('shortener', 'Uses a link shortener, which hides the real destination.', 20);
        }

        $length = strlen($url);
        if ($length > 100) {
            $this->flag('long_url', "The URL is very long ($length characters), a common way to hide the real domain.", 15);
        } elseif ($length > 75) {
            $this->flag('long_url', "The URL is longer than usual ($length characters).", 8);
        }

        if (isset($parts['port']) && !in_array($parts['port'], [80, 443])) {
            $this->flag('port', 'Uses an unusual port (' . $parts['port'] . ').', 10);
        }

        if (str_contains($path, '//')) {
            $this->flag('redirect', 'Contains "//" in the path, which can be used to redirect to another site.', 10);
        }

        if (substr_count($url, '%') >= 5) {
            $this->flag('encoding', 'Contains a lot of encoded characters (%), which can hide what the link really says.', 10);
        }

        $this->checkKeywords($host, $domain, $path);

        return $this->result($host);
    }

    // Brand name in the URL on a domain the brand doesn't own, or a misspelt brand
    private function checkBrand(string $host, string $domain): void
    {
        $name = explode('.', $domain)[0];
        $normalized = strtr($name, ['0' => 'o', '1' => 'l', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '8' => 'b']);
        $normalized = str_replace(['rn', 'vv'], ['m', 'w'], $normalized);

        foreach (self::BRANDS as $brand) {
            if ($name === $brand) {
                continue;
            }

            if ($normalized === $brand || (strlen($brand) >= 5 && levenshtein($name, $brand) === 1)) {
                $this->flag('typosquat', "The domain \"$domain\" imitates \"$brand\" with a small spelling change.", 55);
                return;
            }

            // Brand as a separate word anywhere in the host, e.g. paypal.com.evil.net or paypal-secure.com
            if (preg_match('/(^|[.-])' . $brand . '([.-]|$)/', $host)) {
                $this->flag('brand', "Mentions \"$brand\" but the website is actually \"$domain\", which $brand does not own.", 35);
                return;
            }
        }
    }

    private function checkSubdomains(string $host, string $domain): void
    {
        $sub = substr($host, 0, -strlen($domain));
        $count = $sub === '' ? 0 : substr_count(rtrim($sub, '.'), '.') + 1;

        if (str_starts_with($sub, 'www.')) {
            $count--;
        }

        if ($count >= 3) {
            $this->flag('subdomains', "Has $count subdomains in front of the real domain, often used to look like a trusted site.", 20);
        } elseif ($count === 2) {
            $this->flag('subdomains', 'Has several subdomains in front of the real domain.', 8);
        }
    }

    private function checkHyphens(string $domain): void
    {
        $hyphens = substr_count(explode('.', $domain)[0], '-');

        if ($hyphens >= 2) {
            $this->flag('hyphens', "The domain name has $hyphens hyphens, common in fake sites like secure-login-bank.com.", 15);
        } elseif ($hyphens === 1) {
            $this->flag('hyphens', 'The domain name contains a hyphen.', 5);
        }
    }

    private function checkTld(string $domain): void
    {
        $tld = substr(strrchr($domain, '.'), 1);

        if (in_array($tld, self::RISKY_TLDS, true)) {
            $this->flag('tld', "Uses the \".$tld\" ending, which is cheap and frequently used for phishing.", 15);
        }
    }

    private function checkKeywords(string $host, string $domain, string $path): void
    {
        $haystack = strtolower($host . $path);
        $found = [];
        $inDomain = false;

        foreach (self::KEYWORDS as $word) {
            if (str_contains($haystack, $word)) {
                $found[] = $word;
                $inDomain = $inDomain || str_contains($domain, $word);
            }
        }

        if ($found) {
            $points = min(count($found) * 6, 20);
            $this->flag('keywords', 'Contains words often used to trick people: ' . implode(', ', $found) . '.', $points);
        }

        // Real companies rarely put "login" or "verify" in the domain name itself
        if ($inDomain) {
            $this->flag('keyword_domain', "The domain name \"$domain\" itself contains a trick word like \"secure\" or \"login\".", 10);
        }
    }

    /**
     * "login.paypal.com" -> "paypal.com", "shop.site.com.gh" -> "site.com.gh"
     */
    private function registrableDomain(string $host): string
    {
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) {
            return $host;
        }

        $labels = explode('.', $host);
        $take = in_array(implode('.', array_slice($labels, -2)), self::SECOND_LEVEL, true) ? 3 : 2;

        return implode('.', array_slice($labels, -$take));
    }

    private function inList(string $host, string $domain, array $list): bool
    {
        return in_array($host, $list, true) || in_array($domain, $list, true);
    }

    private function flag(string $rule, string $message, int $points): void
    {
        $this->reasons[] = ['rule' => $rule, 'message' => $message, 'points' => $points];
        $this->score += $points;
    }

    private function result(string $host, ?string $note = null): array
    {
        $score = min($this->score, 100);

        if ($score >= self::PHISHING_AT) {
            $verdict = 'phishing';
        } elseif ($score >= self::SUSPICIOUS_AT) {
            $verdict = 'suspicious';
        } else {
            $verdict = 'safe';
        }

        $reasons = $this->reasons;
        if ($note !== null) {
            $reasons[] = ['rule' => 'whitelist', 'message' => $note, 'points' => 0];
        }

        return [
            'domain'  => $host,
            'score'   => $score,
            'verdict' => $verdict,
            'reasons' => $reasons,
        ];
    }
}
