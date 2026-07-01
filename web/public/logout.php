<?php
declare(strict_types=1);

/**
 * logout.php — meldet den aktuellen Nutzer ab.
 *
 * Nur per POST mit gültigem CSRF-Token, damit die Abmeldung nicht über einen
 * einfachen Link/CSRF erzwungen werden kann.
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;

Auth::start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && Auth::csrfCheck($_POST['csrf_token'] ?? null)) {
    Auth::logout();
}

header('Location: /login.php');
exit;
