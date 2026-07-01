<?php
declare(strict_types=1);

/**
 * nachrichten.php — Posteingang für über kontakt.php eingegangene Nachrichten.
 *
 * Login-geschützt: Die App ist single-tenant (Registrierung ist nach dem
 * ersten Konto geschlossen), daher ist der angemeldete Nutzer immer der
 * Betreiber selbst — ein eigenes Rollensystem ist nicht nötig.
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\ContactRepository;
use App\Database;

Auth::start();
Auth::requireLogin();

$repo = new ContactRepository(Database::connection());

// Aktion "Als gelesen markieren": POST + CSRF, danach PRG zurück auf sich selbst.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (Auth::csrfCheck($_POST['csrf_token'] ?? null)) {
        $id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
        if ($id !== false && $id !== null) {
            $repo->markRead($id);
        }
    }
    header('Location: /nachrichten.php');
    exit;
}

$messages = $repo->listAll();

$pageTitle = 'Nachrichten — IT-Sicherheits-Check';
require __DIR__ . '/web/templates/layout_top.php';
?>

<section>
    <h1 class="h3 fw-bold mb-3">Nachrichten</h1>

    <?php if ($messages === []): ?>
        <div class="card border-0 shadow-sm">
            <div class="card-body text-center text-secondary py-5">
                Noch keine Nachrichten über das Kontaktformular eingegangen.
            </div>
        </div>
    <?php else: ?>
        <div class="card border-0 shadow-sm">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th scope="col">Datum</th>
                            <th scope="col">Name</th>
                            <th scope="col">E-Mail</th>
                            <th scope="col">Nachricht</th>
                            <th scope="col" class="text-center">Status</th>
                            <th scope="col" class="text-end">Aktion</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($messages as $m): ?>
                            <?php
                                $preview = mb_strimwidth((string) $m['message'], 0, 80, '…');
                                $isRead  = (bool) $m['is_read'];
                                try {
                                    $when = (new DateTime((string) $m['created_at']))->format('d.m.Y H:i');
                                } catch (\Throwable $e) {
                                    $when = (string) $m['created_at'];
                                }
                            ?>
                            <tr class="<?= $isRead ? '' : 'fw-semibold' ?>">
                                <td class="text-nowrap"><?= e($when) ?></td>
                                <td><?= e((string) ($m['name'] ?: '—')) ?></td>
                                <td><a href="mailto:<?= e((string) $m['email']) ?>"><?= e((string) $m['email']) ?></a></td>
                                <td class="text-secondary small" style="max-width:320px;"><?= e($preview) ?></td>
                                <td class="text-center">
                                    <?php if ($isRead): ?>
                                        <span class="badge text-bg-secondary">gelesen</span>
                                    <?php else: ?>
                                        <span class="badge text-bg-primary">ungelesen</span>
                                    <?php endif; ?>
                                </td>
                                <td class="text-end">
                                    <?php if (!$isRead): ?>
                                        <form action="/nachrichten.php" method="post" class="m-0">
                                            <input type="hidden" name="csrf_token" value="<?= e(Auth::csrfToken()) ?>">
                                            <input type="hidden" name="id" value="<?= (int) $m['id'] ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-secondary">Als gelesen markieren</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>
</section>

<?php require __DIR__ . '/web/templates/layout_bottom.php'; ?>
