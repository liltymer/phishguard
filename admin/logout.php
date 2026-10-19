<?php
require '../config/db.php';
require '../includes/functions.php';
require '../includes/auth.php';

// Logging out only via POST with a valid token, so a link on another site cannot log the admin out
if ($_SERVER['REQUEST_METHOD'] === 'POST' && verifyCsrf($_POST['csrf_token'] ?? null)) {
    logout();
    header('Location: login.php?notice=logged_out');
    exit;
}

header('Location: index.php');
exit;
