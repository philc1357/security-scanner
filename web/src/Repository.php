<?php
declare(strict_types=1);

namespace App;

use PDO;

/**
 * Repository — Persistenz für Scans und Findings.
 *
 * Sämtliche Datenbankzugriffe erfolgen über PDO mit Prepared Statements.
 * Es werden keine Nutzereingaben direkt in SQL-Strings eingebaut.
 */
final class Repository
{
    public function __construct(private PDO $pdo) {}

    /**
     * Speichert ein Engine-Ergebnis (Scan + zugehörige Findings) in einer Transaktion.
     *
     * @param array    $result Dekodiertes Engine-JSON.
     * @param int|null $userId ID des auslösenden Benutzers (Eigentümer des Scans).
     * @return int Die ID des angelegten Scans.
     */
    public function saveScan(array $result, ?int $userId = null): int
    {
        $summary  = $result['summary'] ?? [];
        $meta     = $result['meta'] ?? [];
        $findings = $result['findings'] ?? [];

        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO scans (user_id, domain, score, rating, reachable, raw_json)
                 VALUES (:user_id, :domain, :score, :rating, :reachable, :raw_json)'
            );
            $stmt->execute([
                ':user_id'   => $userId,
                ':domain'    => (string) ($result['domain'] ?? ''),
                ':score'     => isset($summary['score']) ? (int) $summary['score'] : null,
                ':rating'    => $summary['rating'] ?? null,
                ':reachable' => !empty($meta['reachable']) ? 1 : 0,
                ':raw_json'  => json_encode($result, JSON_UNESCAPED_UNICODE),
            ]);
            $scanId = (int) $this->pdo->lastInsertId();

            $findingStmt = $this->pdo->prepare(
                'INSERT INTO findings
                    (scan_id, finding_key, category, title, severity, status,
                     effort, explanation, recommendation, affected, evidence)
                 VALUES
                    (:scan_id, :finding_key, :category, :title, :severity, :status,
                     :effort, :explanation, :recommendation, :affected, :evidence)'
            );
            foreach ($findings as $f) {
                $findingStmt->execute([
                    ':scan_id'        => $scanId,
                    ':finding_key'    => (string) ($f['id'] ?? ''),
                    ':category'       => (string) ($f['category'] ?? ''),
                    ':title'          => (string) ($f['title'] ?? ''),
                    ':severity'       => (string) ($f['severity'] ?? 'info'),
                    ':status'         => (string) ($f['status'] ?? 'info'),
                    ':effort'         => (string) ($f['effort'] ?? 'mittel'),
                    ':explanation'    => (string) ($f['explanation'] ?? ''),
                    ':recommendation' => (string) ($f['recommendation'] ?? ''),
                    ':affected'       => (string) ($f['affected'] ?? ''),
                    ':evidence'       => (string) ($f['evidence'] ?? ''),
                ]);
            }

            $this->pdo->commit();
            return $scanId;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Lädt das vollständige Engine-Ergebnis eines Scans aus dem archivierten JSON.
     *
     * @return array|null Dekodiertes Engine-JSON oder null, wenn nicht gefunden.
     */
    public function findResult(int $scanId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT raw_json FROM scans WHERE id = :id');
        $stmt->execute([':id' => $scanId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $data = json_decode((string) $row['raw_json'], true);
        return is_array($data) ? $data : null;
    }

    /**
     * Lädt das vollständige Engine-Ergebnis eines Scans, jedoch nur, wenn dieser
     * dem angegebenen Benutzer gehört. Verhindert, dass über eine fremde Scan-ID
     * der Bericht eines anderen Kontos geöffnet werden kann.
     *
     * @return array|null Dekodiertes Engine-JSON oder null, wenn nicht gefunden
     *                    oder nicht im Besitz des Benutzers.
     */
    public function findResultForUser(int $scanId, int $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT raw_json FROM scans WHERE id = :id AND user_id = :uid'
        );
        $stmt->execute([':id' => $scanId, ':uid' => $userId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $data = json_decode((string) $row['raw_json'], true);
        return is_array($data) ? $data : null;
    }

    /**
     * Listet die Scans eines Benutzers für die Dashboard-Übersicht, neueste zuerst.
     * Liefert nur die für die Liste benötigten Spalten (kein raw_json).
     *
     * @return array<int,array<string,mixed>> Zeilen mit id, domain, scanned_at,
     *                                         score, rating, reachable.
     */
    public function listScansForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, domain, scanned_at, score, rating, reachable
               FROM scans
              WHERE user_id = :uid
              ORDER BY scanned_at DESC, id DESC'
        );
        $stmt->execute([':uid' => $userId]);
        return $stmt->fetchAll();
    }
}
