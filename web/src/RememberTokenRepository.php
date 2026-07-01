<?php
declare(strict_types=1);

namespace App;

use PDO;

/**
 * RememberTokenRepository — Persistenz für "Eingeloggt bleiben"-Tokens.
 *
 * Speichert je Token nur den Selector (Lookup-Schlüssel) und den SHA-256-Hash
 * des Validators, niemals den Validator selbst. Sämtliche Zugriffe erfolgen
 * über PDO mit Prepared Statements.
 */
final class RememberTokenRepository
{
    public function __construct(private PDO $pdo) {}

    public function create(int $userId, string $selector, string $validatorHash, string $expiresAt): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO remember_tokens (user_id, selector, validator_hash, expires_at)
             VALUES (:user_id, :selector, :hash, :expires_at)'
        );
        $stmt->execute([
            ':user_id'    => $userId,
            ':selector'   => $selector,
            ':hash'       => $validatorHash,
            ':expires_at' => $expiresAt,
        ]);
    }

    /** @return array|null Datensatz (user_id, validator_hash, expires_at) oder null. */
    public function findBySelector(string $selector): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT user_id, validator_hash, expires_at FROM remember_tokens WHERE selector = :selector'
        );
        $stmt->execute([':selector' => $selector]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function deleteBySelector(string $selector): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM remember_tokens WHERE selector = :selector');
        $stmt->execute([':selector' => $selector]);
    }
}
