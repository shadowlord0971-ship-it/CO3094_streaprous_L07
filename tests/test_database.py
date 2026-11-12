import sqlite3
import tempfile
import unittest
from pathlib import Path

from daemon.database import Database


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.database = Database(":memory:")
        self.addCleanup(self.database.close)

    def test_create_and_lookup_user(self):
        user = self.database.create_user(
            "alice",
            b"password-hash",
            b"salt",
            1000,
            123,
        )

        stored = self.database.get_user("ALICE")
        self.assertEqual(stored["id"], user["id"])
        self.assertEqual(stored["username"], "alice")
        self.assertEqual(stored["password_hash"], b"password-hash")

    def test_usernames_are_unique_case_insensitively(self):
        self.database.create_user("alice", b"hash", b"salt", 1000, 123)

        with self.assertRaises(sqlite3.IntegrityError):
            self.database.create_user("ALICE", b"hash", b"salt", 1000, 124)

    def test_session_lookup_expiry_and_revocation(self):
        user = self.database.create_user(
            "alice",
            b"hash",
            b"salt",
            1000,
            123,
        )
        token_hash = b"hashed-token"
        self.database.create_session(token_hash, user["id"], 100, 200)

        self.assertEqual(
            self.database.get_session_user(token_hash, 150)["username"],
            "alice",
        )
        self.assertIsNone(self.database.get_session_user(token_hash, 200))
        self.assertFalse(self.database.delete_session(token_hash))

    def test_deleting_user_cascades_to_sessions(self):
        user = self.database.create_user(
            "alice",
            b"hash",
            b"salt",
            1000,
            123,
        )
        token_hash = b"hashed-token"
        self.database.create_session(token_hash, user["id"], 100, 200)

        with self.database._lock, self.database._connection:
            self.database._connection.execute(
                "DELETE FROM users WHERE id = ?",
                (user["id"],),
            )

        self.assertIsNone(self.database.get_session_user(token_hash, 150))

    def test_file_database_persists_and_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "accounts.sqlite3"
            database = Database(path)
            database.create_user("alice", b"hash", b"salt", 1000, 123)
            database.close()

            reopened = Database(path)
            try:
                self.assertEqual(reopened.get_user("alice")["username"], "alice")
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
