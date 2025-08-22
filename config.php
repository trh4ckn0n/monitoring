<?php
// ====== CONFIG GLOBALE ======
return [
    // IP à surveiller (attaquant supposé)
    'TARGET_IP' => '192.168.1.50',

    // Interface réseau (ex. eth0, ens33). Laisser null pour auto-détection
    'IFACE' => null,

    // Chemin vers tcpdump
    'TCPDUMP_BIN' => '/usr/sbin/tcpdump',

    // Expression tcpdump additionnelle (optionnelle)
    // ex: 'and not port 22'
    'TCPDUMP_EXTRA' => '',

    // DSN PDO (MySQL ou SQLite). Exemple MySQL:
    // 'DSN' => 'mysql:host=127.0.0.1;dbname=netmon;charset=utf8mb4',
    // 'DB_USER' => 'netmon', 'DB_PASS' => 'motdepasse'
    // Exemple SQLite:
    'DSN' => 'sqlite:' . __DIR__ . '/netmon.sqlite',
    'DB_USER' => null,
    'DB_PASS' => null,

    // Auth simple (login du dashboard)
    'AUTH_EMAIL' => 'admin@example.local',
    // Password hash généré par password_hash('ton_mdp', PASSWORD_DEFAULT)
    'AUTH_PASS_HASH' => '$2y$10$zq6Df0V...remplace_moi...ZC',

    // Alertes e-mail (nouveaux ports détectés)
    'ALERTS_ENABLED' => true,
    'ALERT_EMAIL_TO' => 'soc@example.local',
    'ALERT_EMAIL_FROM' => 'netmon@example.local',
    // anti-spam: re-notifie un port après N minutes si revu
    'ALERT_COOLDOWN_MIN' => 120,

    // Sécurité
    'TRUST_PROXY' => false, // si reverse proxy, active et utilise HTTP_X_FORWARDED_FOR pour IP client

    // Tuning
    'API_PAGE_SIZE' => 50,
];
