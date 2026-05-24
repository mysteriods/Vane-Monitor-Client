"""
SQLite-based logging handler for Vane Monitor.
"""
import logging
import sqlite3
import threading
from datetime import datetime


class SQLiteLogHandler(logging.Handler):
    """A logging.Handler that writes log records into a SQLite database."""

    def __init__(self, db_path: str = 'vane_monitor_log.db'):
        super().__init__()
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            self._local.conn = conn
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                name      TEXT    NOT NULL,
                level     TEXT    NOT NULL,
                message   TEXT    NOT NULL
            )
            '''
        )
        conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC)'
        )
        conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_level ON logs (level)')
        conn.commit()

    def emit(self, record):
        try:
            conn = self._get_conn()
            ts = datetime.utcfromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute(
                'INSERT INTO logs (timestamp, name, level, message) VALUES (?, ?, ?, ?)',
                (ts, record.name, record.levelname, self.format(record)),
            )
            conn.commit()
        except Exception:
            self.handleError(record)

    def close(self):
        try:
            conn = getattr(self._local, 'conn', None)
            if conn is not None:
                conn.close()
                self._local.conn = None
        except Exception:
            pass
        super().close()


def query_logs(db_path: str, offset: int = 0, limit: int = 100,
               search: str = '', level: str = ''):
    """Query log entries from the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                name      TEXT    NOT NULL,
                level     TEXT    NOT NULL,
                message   TEXT    NOT NULL
            )
            '''
        )
        conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_level ON logs (level)')
        conn.commit()

        conditions = []
        params = []

        if level:
            conditions.append('level = ?')
            params.append(level.upper())

        if search:
            conditions.append('message LIKE ?')
            params.append(f'%{search}%')

        where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
        total = conn.execute(f'SELECT COUNT(*) FROM logs{where}', params).fetchone()[0]

        rows = conn.execute(
            f'SELECT timestamp, name, level, message FROM logs{where} ORDER BY id DESC LIMIT ? OFFSET ?',
            params + [limit, offset],
        ).fetchall()

        lines = []
        for row in rows:
            lines.append({
                'timestamp': row['timestamp'],
                'name': row['name'],
                'level': row['level'],
                'message': row['message'],
            })

        return {
            'lines': lines,
            'offset': offset,
            'limit': limit,
            'total': total,
            'has_more': (offset + limit) < total,
        }
    finally:
        conn.close()