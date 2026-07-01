<?php
declare(strict_types=1);

namespace App;

use PDO;

/**
 * UserRepository — Persistenz für Benutzerkonten (Login).
 *
 * Sämtliche Datenbankzugriffe erfolgen über PDO mit Prepared Statements.
 * Es werden keine Nutzereingaben direkt in SQL-Strings eingebaut.
 */
final class UserRepository
{
    public function __construct(private PDO $pdo) {}

    /** Anzahl vorhandener Konten — Grundlage für die Registrierungssperre. */
    public function countUsers(): int
    {
        return (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    }

    /**
     * Sucht ein Konto anhand der E-Mail-Adresse.
     *
     * @return array|null Datensatz (id, email, password_hash, created_at) oder null.
     */
    public function findByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = :email');
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Sucht ein Konto anhand der ID (z.B. für die Auto-Anmeldung per Remember-Cookie).
     *
     * @return array|null Datensatz (id, email, password_hash, created_at) oder null.
     */
    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Legt ein neues Konto an.
     *
     * @param string $passwordHash Bereits erzeugter bcrypt-Hash (password_hash()).
     * @return int Die ID des angelegten Kontos.
     */
    public function create(string $email, string $passwordHash): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (email, password_hash) VALUES (:email, :hash)'
        );
        $stmt->execute([
            ':email' => $email,
            ':hash'  => $passwordHash,
        ]);
        return (int) $this->pdo->lastInsertId();
    }
}
