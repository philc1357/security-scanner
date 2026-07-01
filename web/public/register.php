<?php
declare(strict_types=1);

/**
 * register.php — Registrierung des Erstkontos.
 *
 * Die Registrierung ist nur erlaubt, solange noch kein Konto existiert. Das
 * Passwort muss zweimal eingegeben werden; die Übereinstimmung wird sowohl im
 * Browser (JS, siehe unten) als auch hier im Backend geprüft. Passwörter werden
 * ausschließlich als bcrypt-Hash gespeichert.
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\Database;
use App\Logger;
use App\UserRepository;
use App\Validator;

Auth::start();

if (Auth::check()) {
    header('Location: /dashboard.php');
    exit;
}

$repo = new UserRepository(Database::connection());

// Registrierungssperre: nach dem ersten Konto ist Selbstregistrierung dicht.
$registrationOpen = ($repo->countUsers() === 0);

$error = '';
$email = '';

if ($registrationOpen && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- Backend-Validierung (unabhängig von der JS-Prüfung) ---
    if (!Auth::csrfCheck($_POST['csrf_token'] ?? null)) {
        $error = 'Ungültiges Formular. Bitte erneut versuchen.';
    } else {
        $email           = Validator::normalizeEmail($_POST['email'] ?? '');
        $password        = (string) ($_POST['password'] ?? '');
        $passwordConfirm = (string) ($_POST['password_confirm'] ?? '');

        if ($email === null) {
            $error = 'Bitte geben Sie eine gültige E-Mail-Adresse ein.';
        } elseif (($pwError = Validator::validatePassword($password)) !== null) {
            $error = $pwError;
        } elseif ($password !== $passwordConfirm) {
            $error = 'Die beiden Passwörter stimmen nicht überein.';
        } elseif ($repo->findByEmail($email) !== null) {
            $error = 'Für diese E-Mail-Adresse besteht bereits ein Konto.';
        } else {
            // Konto anlegen, direkt einloggen und zum Dashboard weiterleiten.
            $hash   = password_hash($password, PASSWORD_DEFAULT);
            $userId = $repo->create($email, $hash);
            Auth::login($userId, $email);
            Logger::activity($userId, 'register');
            header('Location: /dashboard.php');
            exit;
        }
    }
    // E-Mail (validierten Wert) für die Wiederbefüllung des Formulars sichern.
    $email = is_string($email) ? $email : (string) ($_POST['email'] ?? '');
}

$pageTitle = 'Registrieren — IT-Sicherheits-Check';
require __DIR__ . '/web/templates/layout_top.php';
?>

<section class="mx-auto" style="max-width: 420px;">
    <h1 class="h3 fw-bold mb-4 text-center">Konto erstellen</h1>

    <?php if (!$registrationOpen): ?>
        <div class="alert alert-warning" role="alert">
            Die Registrierung ist geschlossen — es besteht bereits ein Konto.
        </div>
        <p class="text-center"><a href="/login.php">Zur Anmeldung</a></p>
    <?php else: ?>

        <?php if ($error !== ''): ?>
            <div class="alert alert-danger" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <div class="card shadow-sm">
            <div class="card-body">
                <!-- needs-validation aktiviert die clientseitige Bootstrap-Prüfung -->
                <form action="/register.php" method="post" id="registerForm" class="needs-validation" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= e(Auth::csrfToken()) ?>">

                    <div class="mb-3">
                        <label for="email" class="form-label">E-Mail-Adresse</label>
                        <input type="email" id="email" name="email" class="form-control"
                               value="<?= e($email) ?>" autocomplete="username" required autofocus>
                        <div class="invalid-feedback">Bitte eine gültige E-Mail-Adresse eingeben.</div>
                    </div>

                    <div class="mb-3">
                        <label for="password" class="form-label">Passwort</label>
                        <input type="password" id="password" name="password" class="form-control"
                               autocomplete="new-password" minlength="8" maxlength="72" required>
                        <div class="form-text">Mindestens 8 Zeichen.</div>
                        <div class="invalid-feedback">Bitte ein Passwort mit mindestens 8 Zeichen eingeben.</div>
                    </div>

                    <div class="mb-3">
                        <label for="password_confirm" class="form-label">Passwort wiederholen</label>
                        <input type="password" id="password_confirm" name="password_confirm" class="form-control"
                               autocomplete="new-password" required>
                        <div class="invalid-feedback">Die beiden Passwörter stimmen nicht überein.</div>
                    </div>

                    <button type="submit" class="btn btn-primary w-100">Konto erstellen</button>
                </form>
            </div>
        </div>

        <p class="text-secondary small text-center mt-3">
            Bereits ein Konto? <a href="/login.php">Anmelden</a>
        </p>

        <!-- ----------------------------------------------------------------
             Clientseitige Prüfung: Bootstrap-Validierung + Abgleich der
             beiden Passwortfelder. setCustomValidity blockiert das Absenden,
             solange die Passwörter nicht identisch sind. Die identische Logik
             läuft zusätzlich serverseitig in register.php.
        ----------------------------------------------------------------- -->
        <script>
        (function () {
            const form    = document.getElementById('registerForm');
            const pw       = document.getElementById('password');
            const confirm  = document.getElementById('password_confirm');

            function checkPasswordsMatch() {
                if (confirm.value !== pw.value) {
                    confirm.setCustomValidity('mismatch');
                } else {
                    confirm.setCustomValidity('');
                }
            }
            pw.addEventListener('input', checkPasswordsMatch);
            confirm.addEventListener('input', checkPasswordsMatch);

            form.addEventListener('submit', function (event) {
                checkPasswordsMatch();
                if (!form.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                form.classList.add('was-validated');
            });
        })();
        </script>

    <?php endif; ?>
</section>

<?php require __DIR__ . '/web/templates/layout_bottom.php'; ?>
