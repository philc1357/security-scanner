<?php
declare(strict_types=1);

namespace App;

use PDO;

/**
 * ContactRepository — Persistenz für Kontaktanfragen (kontakt.php / nachrichten.php).
 *
 * Sämtliche Datenbankzugriffe erfolgen über PDO mit Prepared Statements.
 * Es werden keine Nutzereingaben direkt in SQL-Strings eingebaut.
 */
final class ContactRepository
{
    public function __construct(private PDO $pdo) {}

    /** Speichert eine neue Kontaktanfrage. @return int Die ID der angelegten Nachricht. */
    public function create(?string $name, string $email, string $message, ?string $ip, ?string $userAgent): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO contact_messages (name, email, message, ip_address, user_agent)
             VALUES (:name, :email, :message, :ip, :ua)'
        );
        $stmt->execute([
            ':name'    => $name,
            ':email'   => $email,
            ':message' => $message,
            ':ip'      => $ip,
            ':ua'      => $userAgent,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Zählt Einsendungen einer IP innerhalb der letzten $minutes Minuten (Rate-Limiting).
     * :minutes wird explizit als PDO::PARAM_INT gebunden, da INTERVAL keinen
     * impliziten String-Parameter akzeptiert (anders als die übrigen execute([...])-Aufrufe).
     */
    public function countRecentByIp(string $ip, int $minutes): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM contact_messages
              WHERE ip_address = :ip AND created_at > (NOW() - INTERVAL :minutes MINUTE)'
        );
        $stmt->bindValue(':ip', $ip);
        $stmt->bindValue(':minutes', $minutes, PDO::PARAM_INT);
        $stmt->execute();
        return (int) $stmt->fetchColumn();
    }

    /**
     * Listet alle Nachrichten für die Inbox, neueste zuerst.
     *
     * @return array<int,array<string,mixed>>
     */
    public function listAll(): array
    {
        return $this->pdo->query(
            'SELECT id, name, email, message, is_read, created_at
               FROM contact_messages
              ORDER BY created_at DESC, id DESC'
        )->fetchAll();
    }

    /** Markiert eine Nachricht als gelesen. */
    public function markRead(int $id): void
    {
        $stmt = $this->pdo->prepare('UPDATE contact_messages SET is_read = 1 WHERE id = :id');
        $stmt->execute([':id' => $id]);
    }
}
