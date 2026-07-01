<?php
declare(strict_types=1);

/**
 * kontakt.php — "Über mich & Kontakt": Vorstellung des Betreibers und
 * Kontaktformular für Besucher ohne eigene IT-Abteilung.
 *
 * Öffentliche Seite (kein Login nötig). Nachrichten werden ausschließlich in
 * der Datenbank gespeichert (siehe nachrichten.php) — es gibt keinen
 * E-Mail-Versand. Schutz vor Missbrauch: CSRF-Token, Honeypot-Feld und ein
 * IP-basiertes Rate-Limit (siehe unten).
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\ContactRepository;
use App\Database;
use App\Logger;
use App\Validator;

Auth::start();

$error   = '';
$success = isset($_GET['sent']);
$name    = '';
$email   = '';
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Auth::csrfCheck($_POST['csrf_token'] ?? null)) {
        $error = 'Ungültiges Formular. Bitte erneut versuchen.';
    } elseif (($_POST['website'] ?? '') !== '') {
        // Honeypot ausgelöst: wie ein Bot behandeln, aber unauffällig — gleicher
        // Erfolgs-Redirect, ohne dass irgendetwas gespeichert wird.
        header('Location: /kontakt.php?sent=1');
        exit;
    } else {
        $repo = new ContactRepository(Database::connection());
        $ip   = Logger::clientIp();

        if ($ip !== null && $repo->countRecentByIp($ip, 15) >= 3) {
            $error = 'Sie haben in letzter Zeit bereits mehrere Nachrichten gesendet. Bitte versuchen Sie es später erneut.';
        } else {
            $name           = Validator::normalizeContactName($_POST['name'] ?? '');
            $normalizedMail = Validator::normalizeEmail($_POST['email'] ?? '');
            $message        = trim((string) ($_POST['message'] ?? ''));
            $messageError   = Validator::validateContactMessage($message);

            if ($name === null) {
                $error = 'Der Name ist zu lang.';
            } elseif ($normalizedMail === null) {
                $error = 'Bitte geben Sie eine gültige E-Mail-Adresse ein.';
            } elseif ($messageError !== null) {
                $error = $messageError;
            } else {
                $email = $normalizedMail;
                $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 255) : null;
                $repo->create($name !== '' ? $name : null, $email, $message, $ip, $userAgent);
                Logger::activity(null, 'contact_message', $email);
                header('Location: /kontakt.php?sent=1');
                exit;
            }
        }
    }
}

$pageTitle = 'Über mich & Kontakt — IT-Sicherheits-Check';
require __DIR__ . '/web/templates/layout_top.php';
?>

<section class="mx-auto" style="max-width: 720px;">

    <h1 class="h3 fw-bold mb-4">Über mich &amp; Kontakt</h1>

    <!-- ===================================================================
         Über mich: kurze Vorstellung, GitHub-Profil, direkte E-Mail-Alternative.
    ==================================================================== -->
    <div class="panel p-4 p-md-5 mb-5">
        <h2 class="h5 fw-bold mb-2">Philipp Bauer</h2>
        <p class="text-secondary mb-3">
            Ich habe diesen IT-Sicherheits-Check entwickelt, um auch kleinen Unternehmen ohne
            eigene IT-Abteilung eine einfache Möglichkeit zu geben, die Sicherheit ihrer Website
            selbst einzuschätzen — deshalb steht das Werkzeug kostenlos zur Verfügung.
            Hauptberuflich arbeite ich als Softwareentwickler. Wenn Sie Fragen zu Ihrem Befund
            haben oder Unterstützung bei der Webentwicklung oder IT-Sicherheit benötigen — auch im
            Rahmen einer freien Mitarbeit oder eines Projektauftrags — melden Sie sich gerne über
            das Formular unten oder direkt per E-Mail.
        </p>
        <div class="d-flex flex-wrap gap-2">
            <a href="https://github.com/philc1357" target="_blank" rel="noopener" class="btn btn-outline-primary">
                GitHub-Profil ansehen
            </a>
            <a href="mailto:bauer.philipp96@t-online.de" class="btn btn-outline-secondary">
                Direkt per E-Mail schreiben
            </a>
        </div>
    </div>

    <!-- ===================================================================
         Kontaktformular: Name (optional), E-Mail, Nachricht.
    ==================================================================== -->
    <h2 class="h4 fw-bold mb-3">Nachricht senden</h2>

    <?php if ($success): ?>
        <div class="alert alert-success" role="alert">
            Vielen Dank für Ihre Nachricht! Ich melde mich so schnell wie möglich bei Ihnen.
        </div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-danger" role="alert"><?= e($error) ?></div>
    <?php endif; ?>

    <div class="card shadow-sm">
        <div class="card-body">
            <form action="/kontakt.php" method="post" class="needs-validation" novalidate>
                <input type="hidden" name="csrf_token" value="<?= e(Auth::csrfToken()) ?>">

                <!-- Honeypot: für Menschen unsichtbar, für simple Formular-Bots ein Köder -->
                <div style="display:none;" aria-hidden="true">
                    <label for="website">Webseite</label>
                    <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
                </div>

                <div class="mb-3">
                    <label for="name" class="form-label">Name <span class="text-secondary">(optional)</span></label>
                    <input type="text" id="name" name="name" class="form-control" maxlength="100"
                           value="<?= e($name) ?>" autocomplete="name">
                </div>

                <div class="mb-3">
                    <label for="email" class="form-label">E-Mail-Adresse</label>
                    <input type="email" id="email" name="email" class="form-control"
                           value="<?= e($email) ?>" autocomplete="email" required>
                    <div class="form-text">Damit ich Ihnen antworten kann.</div>
                    <div class="invalid-feedback">Bitte eine gültige E-Mail-Adresse eingeben.</div>
                </div>

                <div class="mb-3">
                    <label for="message" class="form-label">Nachricht</label>
                    <textarea id="message" name="message" class="form-control" rows="5"
                              minlength="10" maxlength="5000" required><?= e($message) ?></textarea>
                    <div class="invalid-feedback">Bitte eine Nachricht mit mindestens 10 Zeichen eingeben.</div>
                </div>

                <button type="submit" class="btn btn-primary">Nachricht senden</button>
            </form>
        </div>
    </div>
</section>

<!-- ----------------------------------------------------------------
     Clientseitige Bootstrap-Validierung (rein kosmetisch — die
     verbindliche Prüfung läuft serverseitig oben in dieser Datei).
----------------------------------------------------------------- -->
<script>
(function () {
    const form = document.querySelector('.needs-validation');
    form.addEventListener('submit', function (event) {
        if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }
        form.classList.add('was-validated');
    });
})();
</script>

<?php require __DIR__ . '/web/templates/layout_bottom.php'; ?>
