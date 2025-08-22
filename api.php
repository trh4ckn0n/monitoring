<?php
require __DIR__ . '/utils.php';
require_login();
$pdo = pdo();
$c = cfg();

header('Content-Type: application/json; charset=utf-8');

$route = $_GET['route'] ?? 'stats';

function j($data, $code=200){ http_response_code($code); echo json_encode($data); exit; }

if ($route === 'stats') {
    $total = (int)$pdo->query("SELECT COUNT(*) AS c FROM connections")->fetch()['c'];
    $topPorts = $pdo->query("
      SELECT (CASE WHEN direction='out' THEN dst_port ELSE src_port END) AS port,
             COUNT(*) AS cnt
      FROM connections
      GROUP BY port
      ORDER BY cnt DESC
      LIMIT 10
    ")->fetchAll();
    $last = $pdo->query("SELECT ts FROM connections ORDER BY ts DESC LIMIT 1")->fetch()['ts'] ?? null;
    j(['total'=>$total, 'topPorts'=>$topPorts, 'last'=>$last, 'target'=> $c['TARGET_IP']]);
}

if ($route === 'list') {
    $dir = $_GET['dir'] ?? 'all';
    $port = isset($_GET['port']) ? (int)$_GET['port'] : null;
    $search = trim($_GET['search'] ?? '');
    $page = max(1, (int)($_GET['page'] ?? 1));
    $limit = $c['API_PAGE_SIZE'];
    $offset = ($page-1)*$limit;

    $where = [];
    $params = [];
    if ($dir === 'in') { $where[] = "direction = 'in'"; }
    elseif ($dir === 'out') { $where[] = "direction = 'out'"; }

    if ($port) {
        $where[] = "(src_port = :p OR dst_port = :p)";
        $params[':p'] = $port;
    }
    if ($search !== '') {
        $where[] = "(src_ip LIKE :s OR dst_ip LIKE :s)";
        $params[':s'] = "%$search%";
    }
    $wsql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    $stmt = $pdo->prepare("SELECT * FROM connections $wsql ORDER BY ts DESC LIMIT :lim OFFSET :off");
    foreach ($params as $k=>$v) $stmt->bindValue($k, $v);
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();

    $count = $pdo->query("SELECT COUNT(*) AS c FROM connections $wsql")
                 ->fetch()['c'] ?? 0;

    j(['rows'=>$rows, 'count'=>(int)$count, 'page'=>$page, 'pageSize'=>$limit]);
}

if ($route === 'export') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=connections.csv');
    $from = $_GET['from'] ?? null;
    $to   = $_GET['to'] ?? null;
    $where=[]; $params=[];
    if ($from) { $where[]='ts >= :f'; $params[':f']=$from; }
    if ($to)   { $where[]='ts <= :t'; $params[':t']=$to;   }
    $wsql = $where ? ('WHERE '.implode(' AND ',$where)) : '';
    $stmt = $pdo->prepare("SELECT ts,src_ip,src_port,dst_ip,dst_port,tcp_flags,syn,ack,rst,fin,psh,win,len,direction FROM connections $wsql ORDER BY ts ASC");
    $stmt->execute($params);
    $out = fopen('php://output','w');
    fputcsv($out, ['ts','src_ip','src_port','dst_ip','dst_port','tcp_flags','syn','ack','rst','fin','psh','win','len','direction']);
    while($r=$stmt->fetch()) fputcsv($out, $r);
    exit;
}

j(['error'=>'route not found'], 404);
