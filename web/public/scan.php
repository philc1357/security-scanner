<?php
declare(strict_types=1);

/**
 * scan.php — verarbeitet das Scan-Formular.
 *
 * Ablauf: Eingabe validieren → Scan-Engine aufrufen → Ergebnis speichern →
 * zur Report-Ansicht weiterleiten. Bei jedem Fehler geht es mit einer
 * verständlichen Meldung zurück zum Formular (Post/Redirect/Get).
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\Database;
use App\Logger;
use App\Repository;
use App\ScanRunner;
use App\Validator;

/** Leitet mit einer Fehlermeldung zurück zum Dashboard. */
function back_with_error(string $message): never
{
    header('Location: /dashboard.php?error=' . rawurlencode($message));
    exit;
}

// Login-Pflicht: Scans nur für angemeldete Nutzer.
Auth::start();
Auth::requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /dashboard.php');
    exit;
}

// 1) Nutzereingabe strikt validieren
$domain = Validator::normalizeDomain($_POST['domain'] ?? '');
if ($domain === null) {
    back_with_error('Bitte geben Sie eine gültige Domain ein (z.B. meine-firma.de).');
}

$config = app_config();
$userId = Auth::userId();

// Laufzeit der Engine messen, um sie im scan_log festzuhalten.
$startedAt = microtime(true);

/** Liefert die bisher verstrichene Laufzeit in Millisekunden. */
function elapsed_ms(float $startedAt): int
{
    return (int) round((microtime(true) - $startedAt) * 1000);
}

// 2) Scan-Engine sicher aufrufen
try {
    $runner = new ScanRunner($config['engine'] ?? []);
    $result = $runner->scan($domain);
} catch (\Throwable $e) {
    // Timeout vom übrigen Fehlerfall unterscheiden (Engine-Meldung enthält "Zeitüberschreitung").
    $status = str_contains($e->getMessage(), 'Zeitüberschreitung') ? 'timeout' : 'error';
    Logger::scan($status, $domain, null, $userId, elapsed_ms($startedAt), $e->getMessage());
    back_with_error('Der Scan konnte nicht durchgeführt werden: ' . $e->getMessage());
}

// 3) Ergebnis speichern und zum Report weiterleiten
try {
    $repo = new Repository(Database::connection());
    $scanId = $repo->saveScan($result, $userId);
} catch (\Throwable $e) {
    Logger::scan('error', $domain, null, $userId, elapsed_ms($startedAt), $e->getMessage());
    back_with_error('Das Ergebnis konnte nicht gespeichert werden: ' . $e->getMessage());
}

// Erfolgreichen Lauf protokollieren (scan_log + Audit-Trail).
Logger::scan('success', $domain, $scanId, $userId, elapsed_ms($startedAt), null);
Logger::activity($userId, 'scan', $domain);

header('Location: /report.php?id=' . $scanId);
exit;
