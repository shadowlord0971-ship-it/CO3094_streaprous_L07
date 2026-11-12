"""SQLite persistence for StreapRous accounts and sessions."""

import os
import sqlite3
import threading
import uuid
from pathlib import Path


class Database:
    """Thread-safe SQLite store for authentication data."""

    def __init__(self, path):
        self.path = os.fspath(path)
        if self.path != ":memory:":
            path = Path(self.path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            self.path = os.fspath(path)

        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self):
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    iterations INTEGER NOT NULL CHECK (iterations > 0),
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash BLOB PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id)
                        ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
                    ON sessions(expires_at);

                CREATE TABLE IF NOT EXISTS peers (
                    username TEXT NOT NULL COLLATE NOCASE,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    PRIMARY KEY (username, ip, port)
                );

                CREATE TABLE IF NOT EXISTS channels (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    owner_id TEXT REFERENCES users(id) ON DELETE SET NULL,
                    is_private INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_members (
                    channel_id TEXT NOT NULL REFERENCES channels(id)
                        ON DELETE CASCADE,
                    user_id TEXT NOT NULL REFERENCES users(id)
                        ON DELETE CASCADE,
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, user_id)
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    channel_id TEXT NOT NULL REFERENCES channels(id)
                        ON DELETE CASCADE,
                    sender TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    UNIQUE(channel_id, seq)
                );

                CREATE INDEX IF NOT EXISTS messages_channel_seq_idx
                    ON messages(channel_id, seq);
                """
            )

    @staticmethod
    def _user_record(row):
        if row is None:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": bytes(row["password_hash"]),
            "salt": bytes(row["salt"]),
            "iterations": row["iterations"],
            "created_at": row["created_at"],
        }

    def create_user(self, username, password_hash, salt, iterations, created_at):
        user_id = uuid.uuid4().hex
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO users
                    (id, username, password_hash, salt, iterations, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, password_hash, salt, iterations, created_at),
            )
            row = self._connection.execute(
                """
                SELECT id, username, created_at
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
            return dict(row)

    def get_user(self, username):
        with self._lock:
            row = self._connection.execute(
                """
                SELECT id, username, password_hash, salt, iterations, created_at
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (username,),
            ).fetchone()
        return self._user_record(row)

    def get_user_by_id(self, user_id):
        with self._lock:
            row = self._connection.execute(
                """
                SELECT id, username, created_at
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def create_session(self, token_hash, user_id, created_at, expires_at):
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_hash, user_id, created_at, expires_at),
            )

    def get_session_user(self, token_hash, now):
        with self._lock, self._connection:
            row = self._connection.execute(
                """
                SELECT users.id, users.username, users.created_at
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
            self._connection.execute(
                "DELETE FROM sessions WHERE token_hash = ? AND expires_at <= ?",
                (token_hash, now),
            )
        return dict(row) if row is not None else None

    def delete_session(self, token_hash):
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (token_hash,),
            )
            return cursor.rowcount > 0

    def delete_expired_sessions(self, now):
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM sessions WHERE expires_at <= ?",
                (now,),
            )
            return cursor.rowcount

    @staticmethod
    def _rows(cursor):
        return [dict(row) for row in cursor.fetchall()]

    def create_channel(self, channel_id, name, owner_id, created_at, is_private=0):
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO channels
                    (id, name, owner_id, is_private, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (channel_id, name, owner_id, int(bool(is_private)), created_at),
            )
            row = self._connection.execute(
                "SELECT * FROM channels WHERE id = ?", (channel_id,)
            ).fetchone()
        return dict(row)

    def get_channel(self, channel_id):
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM channels WHERE id = ?", (channel_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def get_channel_by_name(self, name):
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM channels WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
        return dict(row) if row is not None else None

    def list_channels(self, user_id):
        with self._lock:
            cursor = self._connection.execute(
                """
                SELECT channels.*,
                       (SELECT COUNT(*) FROM channel_members AS members
                        WHERE members.channel_id = channels.id) AS member_count,
                       EXISTS(SELECT 1 FROM channel_members AS mine
                              WHERE mine.channel_id = channels.id
                                AND mine.user_id = ?) AS joined
                FROM channels
                ORDER BY channels.name COLLATE NOCASE
                """,
                (user_id,),
            )
            return self._rows(cursor)

    def add_channel_member(self, channel_id, user_id, joined_at):
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO channel_members
                    (channel_id, user_id, joined_at)
                VALUES (?, ?, ?)
                """,
                (channel_id, user_id, joined_at),
            )
            return cursor.rowcount > 0

    def remove_channel_member(self, channel_id, user_id):
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                DELETE FROM channel_members
                WHERE channel_id = ? AND user_id = ?
                """,
                (channel_id, user_id),
            )
            return cursor.rowcount > 0

    def is_channel_member(self, channel_id, user_id):
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1 FROM channel_members
                WHERE channel_id = ? AND user_id = ?
                """,
                (channel_id, user_id),
            ).fetchone()
        return row is not None

    def get_message(self, message_id):
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def append_message(self, message_id, channel_id, sender, body, created_at):
        """Insert one message, assigning the next per-channel sequence number.

        The insert is idempotent: posting the same ``message_id`` twice returns
        the stored row instead of creating a duplicate.
        """
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
            if existing is not None:
                return dict(existing)

            self._connection.execute(
                """
                INSERT INTO messages
                    (id, channel_id, sender, body, created_at, seq)
                SELECT ?, ?, ?, ?, ?,
                       (SELECT COALESCE(MAX(seq), 0) + 1
                        FROM messages WHERE channel_id = ?)
                """,
                (message_id, channel_id, sender, body, created_at, channel_id),
            )
            row = self._connection.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
        return dict(row)

    def list_messages(self, channel_id, since=0, limit=100):
        with self._lock:
            cursor = self._connection.execute(
                """
                SELECT * FROM messages
                WHERE channel_id = ? AND seq > ?
                ORDER BY seq
                LIMIT ?
                """,
                (channel_id, int(since), int(limit)),
            )
            return self._rows(cursor)

    def upsert_peer(self, username, ip, port, last_seen):
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO peers (username, ip, port, last_seen)
                VALUES (?, ?, ?, ?)
                """,
                (username, ip, int(port), int(last_seen)),
            )
            row = self._connection.execute(
                """
                SELECT * FROM peers
                WHERE username = ? COLLATE NOCASE AND ip = ? AND port = ?
                """,
                (username, ip, int(port)),
            ).fetchone()
        return dict(row)

    def list_peers(self, not_before, exclude_username=None):
        query = "SELECT * FROM peers WHERE last_seen >= ?"
        params = [int(not_before)]
        if exclude_username is not None:
            query += " AND username <> ? COLLATE NOCASE"
            params.append(exclude_username)
        query += " ORDER BY username COLLATE NOCASE, port"
        with self._lock:
            cursor = self._connection.execute(query, params)
            return self._rows(cursor)

    def expire_peers(self, not_before):
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM peers WHERE last_seen < ?", (int(not_before),)
            )
            return cursor.rowcount

    def close(self):
        with self._lock:
            self._connection.close()
