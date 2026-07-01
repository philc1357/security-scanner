<?php
declare(strict_types=1);

/**
 * bootstrap.php — gemeinsame Initialisierung für alle Einstiegspunkte.
 *
 * Registriert einen schlanken PSR-4-artigen Autoloader für den Namespace "App"
 * (kein Composer erforderlich) und stellt die Konfiguration bereit.
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'App\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

/**
 * Lädt die Anwendungskonfiguration (config.php).
 */
function app_config(): array
{
    static $config = null;
    if ($config === null) {
        $file = __DIR__ . '/config.php';
        $config = is_file($file) ? require $file : [];
    }
    return $config;
}

/**
 * Kurzschreibweise für HTML-sichere Ausgabe von Nutzer-/Scan-Daten.
 */
function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
