<?php
// Receives the URL from the home page, runs the detector and saves the scan
require 'config/db.php';
require 'includes/Detector.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$url = Detector::normalize($_POST['url'] ?? '', $hadScheme);
if ($url === null || strlen($url) > 2000) {
    header('Location: index.php?error=invalid');
    exit;
}

$pdo = db();
$blacklist = $pdo->query('SELECT domain FROM blacklist')->fetchAll(PDO::FETCH_COLUMN);
$whitelist = $pdo->query('SELECT domain FROM whitelist')->fetchAll(PDO::FETCH_COLUMN);

$result = (new Detector($blacklist, $whitelist))->analyze($url, $hadScheme);

$stmt = $pdo->prepare(
    'INSERT INTO scans (url, domain, score, verdict, reasons, ip_address) VALUES (?, ?, ?, ?, ?, ?)'
);
$stmt->execute([
    $url,
    $result['domain'],
    $result['score'],
    $result['verdict'],
    json_encode($result['reasons']),
    $_SERVER['REMOTE_ADDR'] ?? null,
]);

header('Location: result.php?id=' . $pdo->lastInsertId());
exit;
