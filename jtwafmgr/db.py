"""SQLite storage. One connection per thread, WAL, schema migrations by version number."""
import os
import sqlite3
import threading

SCHEMA = [
    # version 1
    """
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

    CREATE TABLE users (
        username TEXT PRIMARY KEY,
        display_name TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        must_change INTEGER NOT NULL DEFAULT 1,
        totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_last_step INTEGER NOT NULL DEFAULT 0,
        disabled INTEGER NOT NULL DEFAULT 0,
        language TEXT NOT NULL DEFAULT 'en',
        failed_count INTEGER NOT NULL DEFAULT 0,
        locked_until REAL NOT NULL DEFAULT 0,
        last_login REAL,
        created_at REAL NOT NULL
    );

    CREATE TABLE sessions (
        id_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL REFERENCES users(username),
        csrf TEXT NOT NULL,
        created_at REAL NOT NULL,
        last_seen REAL NOT NULL,
        src_ip TEXT
    );
    CREATE INDEX sessions_user ON sessions(username);

    CREATE TABLE tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        scopes TEXT NOT NULL,
        allowed_cidrs TEXT NOT NULL DEFAULT '[]',
        expires_at REAL,
        created_by TEXT NOT NULL,
        created_at REAL NOT NULL,
        last_used_at REAL,
        revoked INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        action TEXT NOT NULL,
        actor TEXT,
        actor_type TEXT NOT NULL,
        src_ip TEXT,
        result TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX audit_ts ON audit(ts);

    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        unique_id TEXT NOT NULL,
        ts REAL NOT NULL,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        query TEXT NOT NULL,
        http_version TEXT,
        src_ip TEXT NOT NULL,
        src_port INTEGER,
        server_port INTEGER,
        origin TEXT NOT NULL,
        status INTEGER,
        engine TEXT,
        outcome TEXT NOT NULL,
        decided_by TEXT,
        anomaly_score INTEGER,
        rule_ids TEXT NOT NULL,
        local_rule_ids TEXT NOT NULL,
        families TEXT NOT NULL,
        message TEXT NOT NULL,
        matches TEXT NOT NULL,
        truncated INTEGER NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX events_uid ON events(node_id, unique_id);
    CREATE INDEX events_ts ON events(ts);
    CREATE INDEX events_host_ts ON events(host, ts);
    CREATE INDEX events_src_ts ON events(src_ip, ts);
    CREATE INDEX events_outcome_ts ON events(outcome, ts);

    CREATE TABLE event_rules (
        event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        rule_id INTEGER NOT NULL,
        ts REAL NOT NULL,
        outcome TEXT NOT NULL
    );
    CREATE INDEX event_rules_rule_ts ON event_rules(rule_id, ts);
    CREATE INDEX event_rules_event ON event_rules(event_id);

    CREATE TABLE stats_daily (
        day TEXT NOT NULL,
        host TEXT NOT NULL,
        rule_id INTEGER NOT NULL,
        origin TEXT NOT NULL,
        outcome TEXT NOT NULL,
        n INTEGER NOT NULL,
        PRIMARY KEY (day, host, rule_id, origin, outcome)
    );

    CREATE TABLE collector_state (
        path TEXT PRIMARY KEY,
        inode INTEGER,
        offset INTEGER NOT NULL,
        updated REAL NOT NULL
    );
    """,
    # version 2: managed rules and the change workflow
    """
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_by TEXT, updated_at REAL);

    CREATE TABLE managed_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER,
        kind TEXT NOT NULL,
        placement TEXT NOT NULL,
        position REAL NOT NULL,
        spec TEXT NOT NULL,
        text TEXT NOT NULL,
        comment TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        deleted INTEGER NOT NULL DEFAULT 0,
        origin TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        change_id INTEGER
    );
    CREATE UNIQUE INDEX managed_rule_id ON managed_rules(rule_id) WHERE rule_id IS NOT NULL;

    CREATE TABLE changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op TEXT NOT NULL,
        kind TEXT NOT NULL,
        item_id INTEGER,
        rule_id INTEGER,
        spec TEXT NOT NULL,
        direction TEXT NOT NULL,
        state TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        proposed_by TEXT NOT NULL,
        proposed_via TEXT NOT NULL DEFAULT 'user',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        base_version INTEGER,
        rule_text TEXT NOT NULL DEFAULT '',
        checks TEXT NOT NULL DEFAULT '{}',
        tests TEXT NOT NULL DEFAULT '[]',
        evidence_override TEXT,
        applied_version INTEGER,
        error TEXT
    );
    CREATE INDEX changes_state ON changes(state, updated_at);

    CREATE TABLE change_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        change_id INTEGER NOT NULL REFERENCES changes(id),
        ts REAL NOT NULL,
        actor TEXT,
        action TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX change_log_change ON change_log(change_id);

    CREATE TABLE versions (
        version INTEGER PRIMARY KEY,
        created_at REAL NOT NULL,
        change_id INTEGER,
        kind TEXT NOT NULL,
        files TEXT NOT NULL,
        hashes TEXT NOT NULL,
        state TEXT NOT NULL,
        result TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE regression_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        source TEXT NOT NULL,
        pinned INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        added_at REAL NOT NULL
    );
    CREATE UNIQUE INDEX regression_unique ON regression_samples(host, method, path);
    """,
    # version 3: compliance -- audit hash chain, account policy, configuration change tracking
    """
    ALTER TABLE audit ADD COLUMN prev_hash TEXT;
    ALTER TABLE audit ADD COLUMN this_hash TEXT;
    ALTER TABLE users ADD COLUMN pw_changed_at REAL;
    ALTER TABLE users ADD COLUMN activity_at REAL;
    ALTER TABLE users ADD COLUMN expires_at REAL;
    ALTER TABLE users ADD COLUMN last_login_ip TEXT;
    ALTER TABLE users ADD COLUMN failed_since_login INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sessions ADD COLUMN user_agent TEXT;
    UPDATE users SET pw_changed_at = created_at, activity_at = COALESCE(last_login, created_at);

    CREATE TABLE password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        changed_at REAL NOT NULL
    );
    CREATE INDEX password_history_user ON password_history(username, id);

    CREATE TABLE config_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        digest TEXT NOT NULL,
        files TEXT NOT NULL,
        changes TEXT NOT NULL DEFAULT '{}',
        cause TEXT NOT NULL DEFAULT ''
    );
    """,
    # version 4
    lambda c: _chain_existing_audit(c),
    # 5: the account responsible for an API token's proposal (the token's creator may not approve it)
    """
    ALTER TABLE changes ADD COLUMN proposed_owner TEXT;
    """,
    # 6: scheduled event analysis with a local LLM (analyst.py): one row per run, kept for transparency
    """
    CREATE TABLE analyst_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        started_at REAL NOT NULL,
        finished_at REAL,
        trigger TEXT NOT NULL DEFAULT 'timer',
        window_hours INTEGER NOT NULL,
        model TEXT NOT NULL DEFAULT '',
        llm_seconds REAL,
        prompt_chars INTEGER NOT NULL DEFAULT 0,
        candidates TEXT NOT NULL DEFAULT '[]',
        verdicts TEXT NOT NULL DEFAULT '[]',
        proposals TEXT NOT NULL DEFAULT '[]',
        skipped TEXT NOT NULL DEFAULT '[]',
        usage TEXT NOT NULL DEFAULT '{}',
        error TEXT,
        reply_excerpt TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX analyst_runs_started ON analyst_runs(started_at);
    """,
    # 7: notifications (one row per message and channel, sent by jt-waf-mgr-notify) and alerts to follow up
    """
    CREATE TABLE notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        event TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        channel TEXT NOT NULL,
        audit_id INTEGER,
        details TEXT NOT NULL DEFAULT '{}',
        dedup TEXT NOT NULL DEFAULT '',
        test INTEGER NOT NULL DEFAULT 0,
        requested_by TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_at REAL NOT NULL,
        sent_at REAL,
        error TEXT
    );
    CREATE INDEX notifications_due ON notifications(status, next_at);
    CREATE INDEX notifications_dedup ON notifications(dedup, channel, created_at);
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        last_seen REAL NOT NULL,
        source TEXT NOT NULL,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        dedup TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 1,
        details TEXT NOT NULL DEFAULT '{}',
        link TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'open',
        handled_by TEXT,
        handled_at REAL,
        note TEXT NOT NULL DEFAULT '',
        reminded_at REAL
    );
    CREATE INDEX alerts_state ON alerts(state, id);
    CREATE INDEX alerts_dedup ON alerts(dedup, state);
    ALTER TABLE analyst_runs ADD COLUMN alerts TEXT NOT NULL DEFAULT '[]';
    ALTER TABLE analyst_runs ADD COLUMN events_scanned INTEGER NOT NULL DEFAULT 0;
    """,
    # 8: request counts from the nginx access logs (traffic.py): per site and hour, numbers only
    """
    CREATE TABLE traffic_hourly (
        hour INTEGER NOT NULL,
        host TEXT NOT NULL,
        total INTEGER NOT NULL DEFAULT 0,
        s2xx INTEGER NOT NULL DEFAULT 0,
        s3xx INTEGER NOT NULL DEFAULT 0,
        s4xx INTEGER NOT NULL DEFAULT 0,
        s5xx INTEGER NOT NULL DEFAULT 0,
        s403 INTEGER NOT NULL DEFAULT 0,
        s444 INTEGER NOT NULL DEFAULT 0,
        s429 INTEGER NOT NULL DEFAULT 0,
        external INTEGER NOT NULL DEFAULT 0,
        bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (hour, host)
    );
    CREATE INDEX traffic_hourly_host ON traffic_hourly(host, hour);
    """,
    # 9: temporary IP blocks (blocks.py): one row per (address, source) while active, kept after it ends
    """
    CREATE TABLE ip_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        source TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'active',
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        created_by TEXT NOT NULL,
        via TEXT NOT NULL,
        token_id TEXT,
        extended INTEGER NOT NULL DEFAULT 0,
        ended_at REAL,
        ended_by TEXT
    );
    CREATE INDEX ip_blocks_active ON ip_blocks(state, ip);
    CREATE INDEX ip_blocks_token ON ip_blocks(token_id, state);
    """,
    # 10: the text of the nginx / ModSecurity configuration files by sha256 (zlib, secret-looking values masked before
    # storing): what an outside change changed, shown as a difference
    """
    CREATE TABLE config_contents (
        sha256 TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        body BLOB NOT NULL,
        created_at REAL NOT NULL
    );
    """,
    # 11: the periodic WAF reviews (review.py): counts and grouped site / path / rule lists, never request content
    """
    CREATE TABLE reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        created_at REAL NOT NULL,
        since REAL NOT NULL,
        until REAL NOT NULL,
        level TEXT NOT NULL,
        trigger TEXT NOT NULL,
        summary TEXT NOT NULL,
        details TEXT NOT NULL
    );
    CREATE INDEX reviews_created ON reviews(created_at);
    """,
]


def _chain_existing_audit(c):
    """Schema 3: hash-chain the audit rows written before the chain existed, then make the table
    append-only (UPDATE and DELETE refused by triggers; the retention purge opens a guarded window)."""
    from .integrity import audit_row_hash, new_genesis
    genesis = new_genesis()
    c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('audit_genesis', ?)", (genesis,))
    prev = genesis
    for r in c.execute('SELECT * FROM audit ORDER BY id').fetchall():
        h = audit_row_hash(prev, r)
        c.execute('UPDATE audit SET prev_hash=?, this_hash=? WHERE id=?', (prev, h, r['id']))
        prev = h
    c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('audit_purge_open', '0')")
    from .integrity import AUDIT_TRIGGERS
    for sql in AUDIT_TRIGGERS.values():
        c.execute(sql)


class Database:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        d = os.path.dirname(path)
        if d and path != ':memory:':
            os.makedirs(d, exist_ok=True)
        self.write_lock = threading.Lock()
        self.migrate()

    def conn(self):
        c = getattr(self._local, 'conn', None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=True)
            c.row_factory = sqlite3.Row
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=NORMAL')
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('PRAGMA busy_timeout=30000')
            self._local.conn = c
            if self.path != ':memory:':
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
        return c

    def release(self):
        """Close this thread's connection (a request thread that ends would otherwise leave it to the garbage
        collector, which Python 3.13+ reports as an unclosed database)."""
        c = getattr(self._local, 'conn', None)
        if c is not None:
            self._local.conn = None
            try:
                c.close()
            except sqlite3.Error:
                pass

    def q(self, sql, args=()):
        return self.conn().execute(sql, args).fetchall()

    def one(self, sql, args=()):
        return self.conn().execute(sql, args).fetchone()

    def x(self, sql, args=()):
        with self.write_lock:
            return self.conn().execute(sql, args)

    def tx(self):
        return _Tx(self)

    def migrate(self):
        c = self.conn()
        with self.write_lock:
            c.execute('BEGIN IMMEDIATE')
            try:
                has_meta = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
                version = 0
                if has_meta:
                    row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                    version = int(row[0]) if row else 0
                for i, script in enumerate(SCHEMA[version:], version + 1):
                    if callable(script):
                        script(c)
                    else:
                        for stmt in script.split(';'):
                            if stmt.strip():
                                c.execute(stmt)
                    c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)", (str(i),))
                c.execute('COMMIT')
            except Exception:
                c.execute('ROLLBACK')
                raise

    def get_meta(self, key, default=None):
        row = self.one('SELECT value FROM meta WHERE key=?', (key,))
        return row[0] if row else default

    def set_meta(self, key, value):
        self.x('INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)', (key, str(value)))


class _Tx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.write_lock.acquire()
        self.c = self.db.conn()
        self.c.execute('BEGIN IMMEDIATE')
        return self.c

    def __exit__(self, exc_type, exc, tb):
        try:
            self.c.execute('ROLLBACK' if exc_type else 'COMMIT')
        finally:
            self.db.write_lock.release()
        return False
