import sqlite3

from app import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('agent','admin','dba')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','dormant','locked')),
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS customers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  rrn TEXT NOT NULL,
  address TEXT NOT NULL,
  assigned_agent_id INTEGER REFERENCES users(id),
  decoy INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_customers_agent ON customers(assigned_agent_id);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  user_id INTEGER,
  username TEXT,
  role TEXT,
  action TEXT NOT NULL,
  resource TEXT,
  detail TEXT,
  ip TEXT,
  result TEXT NOT NULL,
  rows INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  mitre TEXT,
  user_key TEXT NOT NULL,
  username TEXT,
  detail TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  UNIQUE(rule_id, user_key, ts)
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
"""


def connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(customers)")]
        if "decoy" not in cols:  # 기존 DB 마이그레이션
            conn.execute("ALTER TABLE customers ADD COLUMN decoy INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    finally:
        conn.close()


def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
