<?php
/** Kopfbereich des Seitenlayouts (Bootstrap 5 via CDN). Erwartet $pageTitle. */
$pageTitle = $pageTitle ?? 'IT-Sicherheits-Check';
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex">
    <title><?= e($pageTitle) ?></title>
    <!-- Bootstrap 5 via CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
    <!-- Google Fonts: Albert Sans -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Albert+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- Eigene Ergänzungen (Marken-Design, Ampel, Gauge, Druck) -->
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<header>
    <nav class="navbar navbar-dark fixed-top" style="background:var(--brand);">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center gap-2" href="/index.php">
                <span aria-hidden="true">🛡</span>
                <span class="fw-bold">IT-Sicherheits-Check</span>
            </a>
            <div class="d-flex align-items-center gap-3">
                <a href="/kontakt.php" class="nav-link text-white-50 p-0">Kontakt</a>
                <?php if (\App\Auth::check()): ?>
                    <!-- Angemeldeter Nutzer + Abmelden (POST mit CSRF-Schutz) -->
                    <a href="/nachrichten.php" class="nav-link text-white-50 p-0">Nachrichten</a>
                    <span class="navbar-text"><?= e(\App\Auth::userEmail()) ?></span>
                    <form action="/logout.php" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="<?= e(\App\Auth::csrfToken()) ?>">
                        <button type="submit" class="btn btn-outline-light btn-sm">Abmelden</button>
                    </form>
                <?php else: ?>
                    <span class="navbar-text d-none d-sm-inline">Sicherheitsanalyse für kleine Unternehmen</span>
                <?php endif; ?>
            </div>
        </div>
    </nav>
</header>
<main class="container py-4 py-md-5">
