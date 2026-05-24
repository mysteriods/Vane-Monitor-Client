"""Client-side SQLite queue for pending result submissions."""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PendingSubmissionStore:
    """Persist unsent client result batches until the server is reachable again."""

    def __init__(self, db_path: Path, retention_days: int = 14,
                 max_db_size_bytes: int = 100 * 1024 * 1024):
        self.db_path = Path(db_path)
        self.retention_days = retention_days
        self.max_db_size_bytes = max_db_size_bytes
        self._local = threading.local()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA synchronous=NORMAL')
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS pending_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                queued_at TEXT NOT NULL,
                last_attempt_at TEXT,
                client_id TEXT NOT NULL,
                run_serial INTEGER,
                result_count INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                last_error TEXT
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_pending_queued_at
            ON pending_submissions(queued_at)
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_pending_run_serial
            ON pending_submissions(run_serial)
        ''')
        conn.commit()
        self.prune()

    def enqueue(self, client_id: str, run_serial: Optional[int], payload: Dict[str, Any],
                queued_at: Optional[str] = None) -> int:
        conn = self._get_conn()
        queued_at = queued_at or datetime.utcnow().isoformat()
        payload_json = json.dumps(payload)
        result_count = len(payload.get('results', []))

        cursor = conn.execute('''
            INSERT INTO pending_submissions
            (queued_at, client_id, run_serial, result_count, payload_json)
            VALUES (?, ?, ?, ?, ?)
        ''', (queued_at, client_id, run_serial, result_count, payload_json))
        conn.commit()
        self.prune()
        logger.warning(
            "Queued %s result(s) locally for client %s (run_serial=%s)",
            result_count,
            client_id,
            run_serial,
        )
        return int(cursor.lastrowid)

    def list_pending(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute('''
            SELECT id, queued_at, last_attempt_at, client_id, run_serial,
                   result_count, payload_json, last_error
            FROM pending_submissions
            ORDER BY queued_at ASC, id ASC
            LIMIT ?
        ''', (limit,)).fetchall()

        items: List[Dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row['payload_json']) if row['payload_json'] else {}
            items.append({
                'id': row['id'],
                'queued_at': row['queued_at'],
                'last_attempt_at': row['last_attempt_at'],
                'client_id': row['client_id'],
                'run_serial': row['run_serial'],
                'result_count': row['result_count'],
                'payload': payload,
                'last_error': row['last_error'],
            })
        return items

    def has_pending(self) -> bool:
        conn = self._get_conn()
        row = conn.execute('SELECT 1 FROM pending_submissions LIMIT 1').fetchone()
        return row is not None

    def count_pending(self) -> int:
        conn = self._get_conn()
        row = conn.execute('SELECT COUNT(*) AS count FROM pending_submissions').fetchone()
        return int(row['count']) if row else 0

    def mark_attempt(self, submission_id: int, error_text: str) -> None:
        conn = self._get_conn()
        conn.execute('''
            UPDATE pending_submissions
            SET last_attempt_at = ?, last_error = ?
            WHERE id = ?
        ''', (datetime.utcnow().isoformat(), error_text[:1000], submission_id))
        conn.commit()

    def delete(self, submission_id: int) -> None:
        conn = self._get_conn()
        conn.execute('DELETE FROM pending_submissions WHERE id = ?', (submission_id,))
        conn.commit()
        if self._database_size_bytes() > self.max_db_size_bytes or not self.has_pending():
            self._vacuum(conn)

    def prune(self) -> None:
        conn = self._get_conn()
        deleted_any = False
        cutoff = (datetime.utcnow() - timedelta(days=self.retention_days)).isoformat()

        cursor = conn.execute('DELETE FROM pending_submissions WHERE queued_at < ?', (cutoff,))
        if cursor.rowcount:
            deleted_any = True

        conn.commit()

        while self._database_size_bytes() > self.max_db_size_bytes:
            oldest_rows = conn.execute('''
                SELECT id FROM pending_submissions
                ORDER BY queued_at ASC, id ASC
                LIMIT 100
            ''').fetchall()
            if not oldest_rows:
                break

            conn.executemany(
                'DELETE FROM pending_submissions WHERE id = ?',
                [(row['id'],) for row in oldest_rows],
            )
            conn.commit()
            deleted_any = True
            self._vacuum(conn)

        if deleted_any:
            self._vacuum(conn)

    def _database_size_bytes(self) -> int:
        size = 0
        related = [self.db_path, self.db_path.with_name(self.db_path.name + '-wal')]
        related.append(self.db_path.with_name(self.db_path.name + '-shm'))
        for path in related:
            if path.exists():
                size += path.stat().st_size
        return size

    @staticmethod
    def _vacuum(conn: sqlite3.Connection) -> None:
        conn.execute('VACUUM')
        conn.commit()