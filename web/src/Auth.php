<?php
declare(strict_types=1);

namespace App;

/**
 * Auth — Session- und Authentifizierungs-Logik für die Login-Pflicht.
 *
 * Verantwortlich für: gehärtete Session-Cookies, Login-Versuch gegen die
 * Datenbank (password_verify), Zustandsabfragen, Logout, Zugriffsschutz
 * (requireLogin) sowie CSRF-Token für alle POST-Formulare.
 * Passwörter werden ausschließlich als bcrypt-Hash geprüft, niemals geloggt.
 */
final class Auth
{
    /** Name des "Eingeloggt bleiben"-Cookies und seine Gültigkeitsdauer. */
    private const REMEMBER_COOKIE = 'remember_me';
    private const REMEMBER_DAYS   = 30;

    /** Statische Hilfsklasse — keine Instanzen. */
    private function __construct() {}

    // ----------------------------------------------------------------------
    // Session-Start mit gehärteten Cookie-Parametern; ohne aktive Session
    // wird versucht, anhand des Remember-Me-Cookies automatisch anzumelden.
    // ----------------------------------------------------------------------
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        $secure = self::cookiesSecure();
        session_set_cookie_params([
            'httponly' => true,
            'samesite' => 'Lax',
            'secure'   => $secure,
        ]);
        session_start();

        if (!self::check()) {
            self::loginFromRememberCookie();
        }
    }

    // ----------------------------------------------------------------------
    // Login-Versuch: E-Mail + Passwort gegen die Datenbank prüfen
    // ----------------------------------------------------------------------
    public static function attempt(string $email, string $password, bool $remember = false): bool
    {
        $repo = new UserRepository(Database::connection());
        $user = $repo->findByEmail($email);
        if ($user === null || !password_verify($password, (string) $user['password_hash'])) {
            // Fehlgeschlagenen Versuch für die Brute-Force-Erkennung protokollieren.
            Logger::loginAttempt($email, false);
            return false;
        }

        // Session-Fixation verhindern: ID nach erfolgreichem Login erneuern.
        session_regenerate_id(true);
        $_SESSION['user_id']    = (int) $user['id'];
        $_SESSION['user_email'] = (string) $user['email'];

        if ($remember) {
            self::rememberMe((int) $user['id']);
        }

        Logger::loginAttempt($email, true);
        Logger::activity((int) $user['id'], 'login');
        return true;
    }

    /** Meldet eine frisch angelegte/bekannte Nutzer-ID direkt an (z. B. nach Registrierung). */
    public static function login(int $userId, string $email): void
    {
        session_regenerate_id(true);
        $_SESSION['user_id']    = $userId;
        $_SESSION['user_email'] = $email;
    }

    public static function check(): bool
    {
        return isset($_SESSION['user_id']);
    }

    public static function userId(): ?int
    {
        return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    }

    public static function userEmail(): ?string
    {
        return isset($_SESSION['user_email']) ? (string) $_SESSION['user_email'] : null;
    }

    // ----------------------------------------------------------------------
    // Logout: Session vollständig verwerfen
    // ----------------------------------------------------------------------
    public static function logout(): void
    {
        // Nutzer-ID vor dem Verwerfen der Session sichern, um die Abmeldung zu loggen.
        $userId = self::userId();
        if ($userId !== null) {
            Logger::activity($userId, 'logout');
        }

        self::forgetMe();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                [
                    'expires'  => time() - 42000,
                    'path'     => $params['path'],
                    'domain'   => $params['domain'],
                    'secure'   => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite'] ?? 'Lax',
                ]
            );
        }
        session_destroy();
    }

    // ----------------------------------------------------------------------
    // Zugriffsschutz: nicht eingeloggte Besucher zur Login-Seite leiten
    // ----------------------------------------------------------------------
    public static function requireLogin(): void
    {
        if (!self::check()) {
            header('Location: /login.php');
            exit;
        }
    }

    // ----------------------------------------------------------------------
    // "Eingeloggt bleiben": Selector/Validator-Token, 30 Tage gültig.
    // Die DB speichert nur den Selector (Lookup-Schlüssel) und den SHA-256-Hash
    // des Validators – der Validator selbst steckt ausschließlich im Cookie.
    // ----------------------------------------------------------------------
    private static function rememberMe(int $userId): void
    {
        $selector  = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $expiresAt = time() + self::REMEMBER_DAYS * 86400;

        $repo = new RememberTokenRepository(Database::connection());
        $repo->create($userId, $selector, hash('sha256', $validator), date('Y-m-d H:i:s', $expiresAt));

        self::setRememberCookie($selector . ':' . $validator, $expiresAt);
    }

    /** Versucht, anhand des Remember-Me-Cookies automatisch anzumelden (ohne aktive Session). */
    private static function loginFromRememberCookie(): void
    {
        $cookie = (string) ($_COOKIE[self::REMEMBER_COOKIE] ?? '');
        if ($cookie === '' || !str_contains($cookie, ':')) {
            return;
        }
        [$selector, $validator] = explode(':', $cookie, 2);

        $repo  = new RememberTokenRepository(Database::connection());
        $token = $repo->findBySelector($selector);

        // Token unbekannt, abgelaufen oder Validator falsch → Cookie verwerfen.
        if ($token === null
            || strtotime((string) $token['expires_at']) < time()
            || !hash_equals((string) $token['validator_hash'], hash('sha256', $validator))
        ) {
            $repo->deleteBySelector($selector);
            self::clearRememberCookie();
            return;
        }

        $user = (new UserRepository(Database::connection()))->findById((int) $token['user_id']);
        if ($user === null) {
            $repo->deleteBySelector($selector);
            self::clearRememberCookie();
            return;
        }

        // Token rotieren: alten Datensatz verwerfen, neuen Token ausstellen –
        // begrenzt den Schaden, falls das Cookie zwischenzeitlich gestohlen wurde.
        $repo->deleteBySelector($selector);

        session_regenerate_id(true);
        $_SESSION['user_id']    = (int) $user['id'];
        $_SESSION['user_email'] = (string) $user['email'];
        self::rememberMe((int) $user['id']);

        Logger::activity((int) $user['id'], 'login_remember');
    }

    /** Löscht ein vorhandenes Remember-Me-Cookie samt zugehörigem DB-Token. */
    private static function forgetMe(): void
    {
        $cookie = (string) ($_COOKIE[self::REMEMBER_COOKIE] ?? '');
        if ($cookie !== '' && str_contains($cookie, ':')) {
            [$selector] = explode(':', $cookie, 2);
            (new RememberTokenRepository(Database::connection()))->deleteBySelector($selector);
        }
        self::clearRememberCookie();
    }

    private static function setRememberCookie(string $value, int $expiresAt): void
    {
        setcookie(self::REMEMBER_COOKIE, $value, [
            'expires'  => $expiresAt,
            'path'     => '/',
            'secure'   => self::cookiesSecure(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private static function clearRememberCookie(): void
    {
        if (isset($_COOKIE[self::REMEMBER_COOKIE])) {
            setcookie(self::REMEMBER_COOKIE, '', [
                'expires'  => time() - 42000,
                'path'     => '/',
                'secure'   => self::cookiesSecure(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }
    }

    private static function cookiesSecure(): bool
    {
        return ($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off';
    }

    // ----------------------------------------------------------------------
    // CSRF-Schutz für POST-Formulare
    // ----------------------------------------------------------------------
    public static function csrfToken(): string
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return (string) $_SESSION['csrf_token'];
    }

    public static function csrfCheck(?string $token): bool
    {
        return is_string($token)
            && !empty($_SESSION['csrf_token'])
            && hash_equals((string) $_SESSION['csrf_token'], $token);
    }
}
