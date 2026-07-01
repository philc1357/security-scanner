<?php
declare(strict_types=1);

namespace App;

use RuntimeException;

/**
 * ScanRunner — sicherer Aufruf der Python-Scan-Engine.
 *
 * Die Engine wird als separater Prozess gestartet. Sicherheitsvorkehrungen:
 *  - fester, aus der Konfiguration stammender Interpreter- und Skriptpfad,
 *  - die (bereits validierte) Domain wird ausschließlich per escapeshellarg()
 *    übergeben — kein String-Zusammenbau mit Nutzereingaben,
 *  - harte Laufzeitbegrenzung über proc_open, damit kein Prozess hängen bleibt.
 *
 * Rückgabe ist das dekodierte JSON der Engine.
 */
final class ScanRunner
{
    /** @var array{python:string,script:string,timeout_sec:int} */
    private array $config;

    public function __construct(array $engineConfig)
    {
        $this->config = $engineConfig;
    }

    /**
     * Führt einen Scan für die (bereits validierte) Domain aus.
     *
     * @return array Dekodiertes Engine-JSON.
     * @throws RuntimeException bei Start-, Timeout- oder Parse-Fehlern.
     */
    public function scan(string $domain): array
    {
        $script = $this->config['script'];
        if (!is_file($script)) {
            throw new RuntimeException('Scan-Engine nicht gefunden: ' . $script);
        }

        // Befehl aus festen Bestandteilen + escapeshellarg(Domain) zusammensetzen.
        $cmd = escapeshellarg($this->config['python'])
            . ' ' . escapeshellarg($script)
            . ' --target ' . escapeshellarg($domain)
            . ' --json';

        $descriptors = [
            1 => ['pipe', 'w'], // stdout
            2 => ['pipe', 'w'], // stderr
        ];
        $process = proc_open($cmd, $descriptors, $pipes);
        if (!\is_resource($process)) {
            throw new RuntimeException('Scan-Engine konnte nicht gestartet werden.');
        }

        // Nicht-blockierend lesen und nach Ablauf der Frist abbrechen.
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        $deadline = microtime(true) + (int) $this->config['timeout_sec'];

        do {
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            $status = proc_get_status($process);

            if (!$status['running']) {
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($process, 9);
                $this->closeAll($pipes, $process);
                throw new RuntimeException('Scan abgebrochen (Zeitüberschreitung).');
            }
            usleep(50_000); // 50 ms
        } while (true);

        // Restliche Ausgabe einsammeln
        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
        $exitCode = $this->closeAll($pipes, $process);

        $data = json_decode(trim($stdout), true);
        if (!is_array($data)) {
            throw new RuntimeException(
                'Unerwartete Antwort der Scan-Engine.'
                . ($stderr !== '' ? ' Details: ' . trim($stderr) : '')
            );
        }

        // Die Engine meldet kontrollierte Fehler (z.B. SSRF-Schutz) im JSON selbst.
        if (isset($data['error']) && $data['error'] !== null) {
            throw new RuntimeException((string) $data['error']);
        }
        if ($exitCode !== 0 && !isset($data['summary'])) {
            throw new RuntimeException('Scan fehlgeschlagen (Code ' . $exitCode . ').');
        }

        return $data;
    }

    /** Schließt Pipes und Prozess und gibt den Exit-Code zurück. */
    private function closeAll(array $pipes, $process): int
    {
        foreach ($pipes as $pipe) {
            if (\is_resource($pipe)) {
                fclose($pipe);
            }
        }
        return proc_close($process);
    }
}
