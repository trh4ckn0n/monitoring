<?php
function cfg(): array {
    static $cfg;
    if (!$cfg) $cfg = require __DIR__ . '/config.php';
    return $cfg;
}

function pdo(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $c = cfg();
    $pdo = new PDO($c['DSN'], $c['DB_USER'], $c['DB_PASS'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    // SQLite: activer foreign keys
    try { $pdo->exec('PRAGMA foreign_keys = ON'); } catch(Throwable $e) {}
    // Créer tables si SQLite
    if (str_starts_with($c['DSN'], 'sqlite:')) {
        $schema = file_get_contents(__DIR__ . '/schema.sql');
        $pdo->exec($schema);
    }
    return $pdo;
}

// Session sécurisée basique
function start_secure_session(): void {
    $params = session_get_cookie_params();
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => $params['path'],
        'domain'   => $params['domain'],
        'secure'   => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_name('NETMONSESS');
    session_start();
}

function require_login(): void {
    start_secure_session();
    if (empty($_SESSION['user'])) {
        header('Location: /login.php'); exit;
    }
}

function client_ip(): string {
    $c = cfg();
    if ($c['TRUST_PROXY'] && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function send_alert_email(string $subject, string $body): void {
    $c = cfg();
    if (!$c['ALERTS_ENABLED']) return;
    $headers = [
        'From: ' . $c['ALERT_EMAIL_FROM'],
        'Content-Type: text/plain; charset=UTF-8'
    ];
    @mail($c['ALERT_EMAIL_TO'], $subject, $body, implode("\r\n", $headers));
}
