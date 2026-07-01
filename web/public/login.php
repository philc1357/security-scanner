<?php
declare(strict_types=1);

/**
 * login.php — Anmeldung mit E-Mail und Passwort.
 *
 * POST: CSRF prüfen → Auth::attempt → bei Erfolg zur Startseite, sonst
 * generische Fehlermeldung (kein Hinweis darauf, ob die E-Mail existiert).
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\Validator;

Auth::start();

// Bereits eingeloggt? Direkt zum Dashboard.
if (Auth::check()) {
    header('Location: /dashboard.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Auth::csrfCheck($_POST['csrf_token'] ?? null)) {
        $error = 'Ungültiges Formular. Bitte erneut versuchen.';
    } else {
        $email    = Validator::normalizeEmail($_POST['email'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        $remember = !empty($_POST['remember']);

        // Generische Meldung – verrät nicht, ob die E-Mail existiert.
        if ($email !== null && $password !== '' && Auth::attempt($email, $password, $remember)) {
            header('Location: /dashboard.php');
            exit;
        }
        $error = 'E-Mail oder Passwort ist falsch.';
    }
}

$pageTitle = 'Anmelden — IT-Sicherheits-Check';
require __DIR__ . '/web/templates/layout_top.php';
?>

<section class="mx-auto" style="max-width: 420px;">
    <h1 class="h3 fw-bold mb-4 text-center">Anmelden</h1>

    <?php if ($error !== ''): ?>
        <div class="alert alert-danger" role="alert"><?= e($error) ?></div>
    <?php endif; ?>

    <div class="card shadow-sm">
        <div class="card-body">
            <form action="/login.php" method="post">
                <input type="hidden" name="csrf_token" value="<?= e(Auth::csrfToken()) ?>">

                <div class="mb-3">
                    <label for="email" class="form-label">E-Mail-Adresse</label>
                    <input type="email" id="email" name="email" class="form-control"
                           autocomplete="username" required autofocus>
                </div>

                <div class="mb-3">
                    <label for="password" class="form-label">Passwort</label>
                    <input type="password" id="password" name="password" class="form-control"
                           autocomplete="current-password" required>
                </div>

                <div class="mb-3 form-check">
                    <input type="checkbox" id="remember" name="remember" value="1" class="form-check-input">
                    <label for="remember" class="form-check-label">30 Tage angemeldet bleiben</label>
                </div>

                <button type="submit" class="btn btn-primary w-100">Anmelden</button>
            </form>
        </div>
    </div>

    <p class="text-secondary small text-center mt-3">
        Noch kein Konto? <a href="/register.php">Registrieren</a>
    </p>
</section>

<?php require __DIR__ . '/web/templates/layout_bottom.php'; ?>
