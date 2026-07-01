<?php
declare(strict_types=1);

namespace App;

/**
 * Validator — strikte Eingabevalidierung.
 *
 * Nutzereingaben werden grundsätzlich als nicht vertrauenswürdig behandelt.
 * Die Domain wird per Allowlist-Regex geprüft, bevor sie an die Scan-Engine
 * weitergereicht wird. Alles, was nicht eindeutig als gültige Domain erkennbar
 * ist, wird abgelehnt — das verhindert sowohl Unsinn-Eingaben als auch
 * Einschleusungsversuche.
 */
final class Validator
{
    // Gültige Domain: Labels aus a-z 0-9 und Bindestrich (nicht am Rand),
    // mindestens zwei Labels, TLD aus Buchstaben. Keine IPs, Ports, Pfade, Schemata.
    private const DOMAIN_PATTERN =
        '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/';

    /**
     * Normalisiert eine Roh-Eingabe zu einem reinen Domainnamen.
     *
     * @return string|null Der bereinigte Domainname oder null bei ungültiger Eingabe.
     */
    public static function normalizeDomain(string $raw): ?string
    {
        $value = strtolower(trim($raw));

        // Schema, Pfad und Port entfernen (falls der Nutzer eine volle URL eingibt)
        $value = (string) preg_replace('#^[a-z]+://#', '', $value);
        $value = explode('/', $value)[0];
        $value = explode(':', $value)[0];
        $value = rtrim($value, '.');

        if ($value === '' || !preg_match(self::DOMAIN_PATTERN, $value)) {
            return null;
        }
        return $value;
    }

    // ----------------------------------------------------------------------
    // Login/Registrierung: E-Mail- und Passwort-Validierung
    // ----------------------------------------------------------------------

    /** Minimal- und Maximallänge für Passwörter (bcrypt verarbeitet max. 72 Byte). */
    private const PASSWORD_MIN = 8;
    private const PASSWORD_MAX = 72;

    /**
     * Normalisiert und prüft eine E-Mail-Adresse.
     *
     * @return string|null Die bereinigte (kleingeschriebene) Adresse oder null bei ungültig.
     */
    public static function normalizeEmail(string $raw): ?string
    {
        $value = strtolower(trim($raw));
        if ($value === '' || strlen($value) > 254) {
            return null;
        }
        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
            return null;
        }
        return $value;
    }

    /**
     * Prüft ein Passwort gegen die Mindestanforderungen.
     *
     * @return string|null Fehlermeldung bei Verstoß, oder null wenn das Passwort gültig ist.
     */
    public static function validatePassword(string $password): ?string
    {
        $length = strlen($password);
        if ($length < self::PASSWORD_MIN) {
            return 'Das Passwort muss mindestens ' . self::PASSWORD_MIN . ' Zeichen lang sein.';
        }
        if ($length > self::PASSWORD_MAX) {
            return 'Das Passwort darf höchstens ' . self::PASSWORD_MAX . ' Zeichen lang sein.';
        }
        return null;
    }

    // ----------------------------------------------------------------------
    // Kontaktformular (kontakt.php): Namens- und Nachrichtenlänge
    // ----------------------------------------------------------------------

    private const CONTACT_NAME_MAX    = 100;
    private const CONTACT_MESSAGE_MIN = 10;
    private const CONTACT_MESSAGE_MAX = 5000;

    /**
     * Bereinigt den optionalen Namen im Kontaktformular.
     *
     * @return string|null Getrimmter Name (ggf. leer) oder null, wenn zu lang.
     */
    public static function normalizeContactName(string $raw): ?string
    {
        $value = trim($raw);
        if (mb_strlen($value) > self::CONTACT_NAME_MAX) {
            return null;
        }
        return $value;
    }

    /**
     * Prüft die Nachricht des Kontaktformulars gegen Mindest- und Maximallänge.
     *
     * @return string|null Fehlermeldung bei Verstoß, oder null wenn die Nachricht gültig ist.
     */
    public static function validateContactMessage(string $message): ?string
    {
        $length = mb_strlen(trim($message));
        if ($length < self::CONTACT_MESSAGE_MIN) {
            return 'Bitte geben Sie eine Nachricht mit mindestens ' . self::CONTACT_MESSAGE_MIN . ' Zeichen ein.';
        }
        if ($length > self::CONTACT_MESSAGE_MAX) {
            return 'Die Nachricht darf höchstens ' . self::CONTACT_MESSAGE_MAX . ' Zeichen lang sein.';
        }
        return null;
    }
}
