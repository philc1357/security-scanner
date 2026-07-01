<?php
declare(strict_types=1);

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\Database;
use App\Repository;

// Login-Pflicht: Berichte nur für angemeldete Nutzer.
Auth::start();
Auth::requireLogin();

// --- Scan-ID prüfen und Ergebnis laden ---
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id === null || $id < 1) {
    header('Location: /dashboard.php?error=' . rawurlencode('Ungültiger Bericht.'));
    exit;
}

try {
    // Nur Berichte laden, die dem angemeldeten Nutzer gehören.
    $repo = new Repository(Database::connection());
    $result = $repo->findResultForUser($id, (int) Auth::userId());
} catch (\Throwable $e) {
    header('Location: /dashboard.php?error=' . rawurlencode('Bericht nicht ladbar: ' . $e->getMessage()));
    exit;
}

if ($result === null) {
    header('Location: /dashboard.php?error=' . rawurlencode('Bericht nicht gefunden.'));
    exit;
}

$pageTitle = 'Sicherheitsbericht — ' . ($result['domain'] ?? '');
require __DIR__ . '/web/templates/layout_top.php';
require __DIR__ . '/web/templates/report_body.php';
require __DIR__ . '/web/templates/layout_bottom.php';
