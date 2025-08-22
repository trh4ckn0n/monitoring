#!/usr/bin/env php
<?php
require __DIR__ . '/utils.php';

$c = cfg();
$pdo = pdo();

// Détection interface si besoin
$iface = $c['IFACE'];
if (!$iface) {
    // tentative simple: première interface UP trouvée via iproute2
    $iface = trim(shell_exec("ip -o link show | awk -F': ' '/state UP/{print $2; exit}'"));
    if (!$iface) $iface = 'any';
}

$filter = sprintf('host %s and tcp %s', escapeshellarg($c['TARGET_IP']), $c['TCPDUMP_EXTRA'] ? $c['TCPDUMP_EXTRA'] : '');
$cmd = sprintf(
    '%s -i %s -nn -tttt -l %s',
    escapeshellcmd($c['TCPDUMP_BIN']),
    escapeshellarg($iface),
    $filter
);

echo "[*] Starting tcpdump: $cmd\n";
$descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w']
];
$proc = proc_open($cmd, $descriptors, $pipes);
if (!is_resource($proc)) {
    fwrite(STDERR, "Failed to start tcpdump\n");
    exit(1);
}
stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);

$insert = $pdo->prepare("
INSERT OR IGNORE INTO connections
(ts, src_ip, src_port, dst_ip, dst_port, tcp_flags, syn, ack, rst, fin, psh, win, len, direction)
VALUES (:ts, :src_ip, :src_port, :dst_ip, :dst_port, :tcp_flags, :syn, :ack, :rst, :fin, :psh, :win, :len, :direction)
");

// pour les alertes “nouveau port”
$selSeen = $pdo->prepare("SELECT id, last_alert FROM seen_ports WHERE target_ip = :tip AND port = :p");
$insSeen = $pdo->prepare("INSERT INTO seen_ports (target_ip, port, first_seen, last_alert) VALUES (:tip, :p, :ts, :ts)
                          ON CONFLICT(target_ip, port) DO NOTHING");
$updSeen = $pdo->prepare("UPDATE seen_ports SET last_alert = :ts WHERE target_ip = :tip AND port = :p");

$cooldown = max(1, (int)$c['ALERT_COOLDOWN_MIN']);

$targetIp = $c['TARGET_IP'];

echo "[*] Monitoring TCP traffic for {$targetIp} on iface {$iface}\n";

while (is_resource($proc)) {
    $line = fgets($pipes[1]);
    if ($line === false) {
        usleep(50000);
        continue;
    }

    // Exemple de ligne (tcpdump -nn -tttt):
    // 2025-08-22 13:05:10.123456 IP 192.168.1.50.54321 > 10.0.0.5.80: Flags [S], seq 123, win 64240, length 0
    $line = trim($line);
    if ($line === '') continue;

    // Timestamp (jusqu’à microsecondes)
    if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)/', $line, $m)) {
        // essaie autre format (sans microsecondes)
        if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/', $line, $m)) continue;
    }
    $ts = $m[1];

    // Parse src/dst + ports
    // ... IP SRC.SPORT > DST.DPORT:
    if (!preg_match('/IP\s+([0-9\.]+)\.(\d+)\s+>\s+([0-9\.]+)\.(\d+):\s+(.*)$/', $line, $m)) {
        // parfois c'est DST > SRC (retour), on tente l’inverse
        if (!preg_match('/IP\s+([0-9\.]+)\.(\d+)\s+<\s+([0-9\.]+)\.(\d+):\s+(.*)$/', $line, $m)) {
            continue;
        }
    }
    $src_ip = $m[1];
    $src_port = (int)$m[2];
    $dst_ip = $m[3];
    $dst_port = (int)$m[4];
    $rest = $m[5];

    $direction = ($src_ip === $targetIp) ? 'out' : (($dst_ip === $targetIp) ? 'in' : 'out');

    // Flags
    $flags = '';
    $syn = $ack = $rst = $fin = $psh = 0;
    if (preg_match('/Flags\s+\[([^\]]+)\]/', $rest, $fm)) {
        $flags = $fm[1]; // ex: S, SA, R, F, P, ...
        $syn = (int) (strpos($flags, 'S') !== false);
        $ack = (int) (strpos($flags, 'A') !== false);
        $rst = (int) (strpos($flags, 'R') !== false);
        $fin = (int) (strpos($flags, 'F') !== false);
        $psh = (int) (strpos($flags, 'P') !== false);
    }

    // window/len si présents
    $win = null; $len = null;
    if (preg_match('/win\s+(\d+)/', $rest, $wm)) $win = (int)$wm[1];
    if (preg_match('/length\s+(\d+)/', $rest, $lm)) $len = (int)$lm[1];

    try {
        $insert->execute([
            ':ts' => $ts,
            ':src_ip' => $src_ip,
            ':src_port' => $src_port,
            ':dst_ip' => $dst_ip,
            ':dst_port' => $dst_port,
            ':tcp_flags' => $flags,
            ':syn' => $syn,
            ':ack' => $ack,
            ':rst' => $rst,
            ':fin' => $fin,
            ':psh' => $psh,
            ':win' => $win,
            ':len' => $len,
            ':direction' => $direction
        ]);
    } catch (Throwable $e) {
        // doublon -> ignore
    }

    // Alerte si “nouveau port vu” vers/depuis target
    $portObserved = ($src_ip === $targetIp) ? $dst_port : (($dst_ip === $targetIp) ? $src_port : null);
    if ($portObserved !== null) {
        // Vérifier/Insérer dans seen_ports
        $now = (new DateTime($ts))->format('Y-m-d H:i:s');
        $insSeen->execute([':tip'=>$targetIp, ':p'=>$portObserved, ':ts'=>$now]);

        $selSeen->execute([':tip'=>$targetIp, ':p'=>$portObserved]);
        if ($row = $selSeen->fetch()) {
            $last = $row['last_alert'];
            $alert = false;
            if ($last === null) $alert = true;
            else {
                $lastDt = new DateTime($last);
                $curDt  = new DateTime($now);
                $mins = ($curDt->getTimestamp() - $lastDt->getTimestamp())/60;
                if ($mins >= $cooldown) $alert = true;
            }
            if ($alert) {
                $subject = "[NETMON] Nouveau port observé: {$portObserved}/tcp pour {$targetIp}";
                $body = "IP: {$targetIp}\nPort: {$portObserved}/tcp\nDirection: {$direction}\nVu le: {$now}\nExtrait tcpdump: {$line}\n";
                send_alert_email($subject, $body);
                $updSeen->execute([':ts'=>$now, ':tip'=>$targetIp, ':p'=>$portObserved]);
                echo "[ALERT] {$subject}\n";
            }
        }
    }
}
