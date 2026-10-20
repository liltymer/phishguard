<?php
/**
 * Quick check of the detection engine. Run from the project folder:
 *   C:\xampp\php\php.exe tests\detector_test.php
 */
require __DIR__ . '/../includes/Detector.php';

$blacklist = ['evil-phish.com'];
$whitelist = ['google.com', 'paypal.com', 'github.com'];
$detector  = new Detector($blacklist, $whitelist);

// [input, expected verdict]
$cases = [
    ['https://www.google.com', 'safe'],
    ['https://github.com/liltymer/phishguard', 'safe'],
    ['https://www.knust.edu.gh', 'safe'],
    ['https://medium.com/@someone/my-article', 'safe'],
    ['example.com', 'safe'],
    ['http://evil-phish.com/anything', 'phishing'],
    ['http://paypa1.com/signin', 'phishing'],
    ['http://paypal.com@198.51.100.7/login', 'phishing'],
    ['http://192.168.4.21/bank/login.php', 'phishing'],
    ['http://paypal.com.secure-account.verify-user.xyz/webscr?cmd=login', 'phishing'],
    ['https://secure-login-update.tk/account/verify', 'phishing'],
    ['https://bit.ly/3xYz12', 'safe'],
    ['http://mtn-momo-reward.com/claim', 'phishing'],
    ['https://mtn-promo.com', 'suspicious'],
    ['https://my-shop.com/account', 'safe'],
    ['https://faceb00k.com/login', 'phishing'],
    ['https://xn--pypal-4ve.com/login', 'suspicious'],
    ['http://example.com:8080//evil.com/%2F%3A%40%2E%2E', 'suspicious'],
    ['https://example.com/' . str_repeat('a', 90), 'safe'],
];

$passed = 0;
$triggered = [];
foreach ($cases as [$input, $expected]) {
    $url = Detector::normalize($input, $hadScheme);
    $r = $detector->analyze($url, $hadScheme);
    $ok = $r['verdict'] === $expected;
    $passed += $ok;
    $triggered += array_flip(array_column($r['reasons'], 'rule'));

    printf("%s %-68s %3d %-10s (expected %s)\n", $ok ? 'PASS' : 'FAIL', $input, $r['score'], $r['verdict'], $expected);
    foreach ($r['reasons'] as $reason) {
        printf("       +%-3d %s\n", $reason['points'], $reason['message']);
    }
}

foreach (['', 'not a url', 'ftp://files.com', 'javascript:alert(1)'] as $bad) {
    $ok = Detector::normalize($bad) === null;
    $passed += $ok;
    printf("%s rejects invalid input \"%s\"\n", $ok ? 'PASS' : 'FAIL', $bad);
}

// The How It Works page lists Detector::RULES, so it must match what the engine really does
unset($triggered['whitelist']);
$undocumented = array_diff(array_keys($triggered), array_keys(Detector::RULES));
$untested = array_diff(array_keys(Detector::RULES), array_keys($triggered));

$ok = !$undocumented;
$passed += $ok;
printf("%s every triggered rule is documented in Detector::RULES%s\n", $ok ? 'PASS' : 'FAIL',
    $ok ? '' : ' (missing: ' . implode(', ', $undocumented) . ')');

$ok = !$untested;
$passed += $ok;
printf("%s every documented rule is triggered by a test case%s\n", $ok ? 'PASS' : 'FAIL',
    $ok ? '' : ' (never triggered: ' . implode(', ', $untested) . ')');

$total = count($cases) + 4 + 2;
echo "\n$passed / $total passed\n";
exit($passed === $total ? 0 : 1);
