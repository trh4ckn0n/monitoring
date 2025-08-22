-- TABLE connexions: chaque tentative/flux TCP vu par tcpdump
CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER NOT NULL,
  dst_ip TEXT NOT NULL,
  dst_port INTEGER NOT NULL,
  tcp_flags TEXT,
  syn INTEGER DEFAULT 0,
  ack INTEGER DEFAULT 0,
  rst INTEGER DEFAULT 0,
  fin INTEGER DEFAULT 0,
  psh INTEGER DEFAULT 0,
  win INTEGER DEFAULT NULL,
  len INTEGER DEFAULT NULL,
  direction TEXT CHECK(direction in ('in','out')) NOT NULL,
  UNIQUE(ts, src_ip, src_port, dst_ip, dst_port, tcp_flags)
);

-- Pour savoir quels ports sont "nouveaux"
CREATE TABLE IF NOT EXISTS seen_ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  first_seen DATETIME NOT NULL,
  last_alert DATETIME,
  UNIQUE(target_ip, port)
);

-- Pour sessions (si SQLite: on évite le fichier par défaut si besoin)
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);
