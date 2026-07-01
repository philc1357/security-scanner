<?php
declare(strict_types=1);

namespace App;

use PDO;
use RuntimeException;

/**
 * Database — zentrale PDO-Verbindung (Singleton).
 *
 * Liefert eine PDO-Instanz mit sicheren Standardeinstellungen:
 * echte Prepared Statements, Exceptions bei Fehlern und assoziative Ergebnisse.
 * Alle SQL-Zugriffe der Anwendung laufen ausschließlich über PDO/Prepared Statements.
 */
final class Database
{
    private static ?PDO $instance = null;

    /** Statische Hilfsklasse — keine Instanzen. */
    private function __construct() {}

    public static function connection(): PDO
    {
        if (self::$instance instanceof PDO) {
            return self::$instance;
        }

        $configFile = dirname(__DIR__) . '/config.php';
        if (!is_file($configFile)) {
            throw new RuntimeException(
                'config.php fehlt. Bitte config.php.example kopieren und anpassen.'
            );
        }
        $config = require $configFile;
        $db = $config['db'] ?? [];

        self::$instance = new PDO(
            $db['dsn'] ?? '',
            $db['user'] ?? '',
            $db['password'] ?? '',
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false, // echte Prepared Statements
            ]
        );

        return self::$instance;
    }
}
