<?php
declare(strict_types=1);

namespace App;

use PDO;
use Throwable;

/**
 * Logger — schreibt Audit-/Sicherheits-Logs in die Datenbank.
 *
 * Statische Helfer-Klasse (analog zu App\Auth), damit die Aufrufstellen schlank
 * bleiben. Schreibt in die Tabellen login_attempts, activity_log und scan_log –
 * ausschließlich über PDO/Prepared Statements.
 *
 * Wichtig: Logging darf den Nutzer-Flow niemals blockieren. Jede Methode kapselt
 * den Datenbankzugriff in try/catch und schluckt Fehler (kein erneutes Werfen),
 * damit ein Logging-Problem weder Login noch Scan unterbricht.
 */
final class Logger
{
    /** Statische Hilfsklasse — keine Instanzen. */
    private function __construct() {}

    // ----------------------------------------------------------------------
    // Login-Versuch protokollieren (Brute-Force-Grundlage)
    // ----------------------------------------------------------------------
    public static function loginAttempt(?string $email, bool $success): void
    {
        try {
            $stmt = Database::connection()->prepare(
                'INSERT INTO login_attempts (email, ip_address, user_agent, success)
                 VALUES (:email, :ip, :ua, :success)'
            );
            $stmt->execute([
                ':email'   => self::clip($email, 254),
                ':ip'      => self::clientIp(),
                ':ua'      => self::userAgent(),
                ':success' => $success ? 1 : 0,
            ]);
        } catch (Throwable $e) {
            // Logging-Fehler bewusst ignorieren – darf den Login nicht stören.
        }
    }

    // ----------------------------------------------------------------------
    // Nutzeraktion im Audit-Trail festhalten (register, login, logout, scan)
    // ----------------------------------------------------------------------
    public static function activity(?int $userId, string $action, ?string $detail = null): void
    {
        try {
            $stmt = Database::connection()->prepare(
                'INSERT INTO activity_log (user_id, action, ip_address, detail)
                 VALUES (:user_id, :action, :ip, :detail)'
            );
            $stmt->execute([
                ':user_id' => $userId,
                ':action'  => self::clip($action, 50),
                ':ip'      => self::clientIp(),
                ':detail'  => self::clip($detail, 255),
            ]);
        } catch (Throwable $e) {
            // Logging-Fehler bewusst ignorieren.
        }
    }

    // ----------------------------------------------------------------------
    // Engine-Lauf protokollieren (Erfolg, Timeout oder Fehler)
    // ----------------------------------------------------------------------
    public static function scan(
        string $status,
        ?string $domain,
        ?int $scanId,
        ?int $userId,
        ?int $durationMs,
        ?string $message
    ): void {
        try {
            $stmt = Database::connection()->prepare(
                'INSERT INTO scan_log (scan_id, user_id, domain, status, duration_ms, message)
                 VALUES (:scan_id, :user_id, :domain, :status, :duration_ms, :message)'
            );
            $stmt->execute([
                ':scan_id'     => $scanId,
                ':user_id'     => $userId,
                ':domain'      => self::clip($domain, 253),
                ':status'      => $status,
                ':duration_ms' => $durationMs,
                ':message'     => $message,
            ]);
        } catch (Throwable $e) {
            // Logging-Fehler bewusst ignorieren – darf den Scan-Flow nicht stören.
        }
    }

    // ----------------------------------------------------------------------
    // Interne Helfer: Request-Metadaten und Längenbegrenzung
    // ----------------------------------------------------------------------

    /** Client-IP aus der Request-Umgebung (oder null, z.B. auf CLI). */
    public static function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        return $ip !== '' ? substr((string) $ip, 0, 45) : null;
    }

    /** User-Agent, auf die Spaltenlänge gekürzt. */
    private static function userAgent(): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        return $ua !== '' ? substr((string) $ua, 0, 255) : null;
    }

    /** Kürzt einen Wert sicher auf die Spaltenlänge; null bleibt null. */
    private static function clip(?string $value, int $maxLength): ?string
    {
        if ($value === null) {
            return null;
        }
        return mb_substr($value, 0, $maxLength);
    }
}
