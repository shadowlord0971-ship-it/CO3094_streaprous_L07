"""Tests for the chat service and its SQLite schema."""

import unittest

from daemon.chat import ChatService
from daemon.database import Database
from daemon.errors import BadRequest, Forbidden, NotFound


class ChatTestCase(unittest.TestCase):
    def setUp(self):
        self.database = Database(":memory:")
        self.addCleanup(self.database.close)
        self.now = 1_700_000_000
        self.user = self.database.create_user(
            "alice", b"hash", b"salt", 1000, self.now
        )
        self.bob = self.database.create_user(
            "bob", b"hash", b"salt", 1000, self.now
        )
        self.service = ChatService(self.database, clock=lambda: self.now)


class ChannelTests(ChatTestCase):
    def test_create_channel_joins_owner(self):
        channel = self.service.create_channel("general", self.user)
        self.assertEqual(channel["name"], "general")
        self.assertEqual(channel["member_count"], 1)
        self.assertTrue(self.database.is_channel_member(channel["id"], self.user["id"]))
        listed = self.service.list_channels(self.user["id"])
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["joined"], 1)

    def test_duplicate_name_is_rejected_case_insensitively(self):
        self.service.create_channel("General", self.user)
        with self.assertRaises(ValueError):
            self.service.create_channel("general", self.user)

    def test_invalid_names_are_rejected(self):
        for name in ("", "   ", "-dash", "x" * 33, "bad\nname"):
            with self.subTest(name=name):
                with self.assertRaises(BadRequest):
                    self.service.create_channel(name, self.user)

    def test_join_leave_and_membership_check(self):
        channel = self.service.create_channel("general", self.user)
        self.assertTrue(self.service.join(channel["id"], self.bob))
        self.assertFalse(self.service.join(channel["id"], self.bob))
        self.service.require_member(channel["id"], self.bob)
        self.assertTrue(self.service.leave(channel["id"], self.bob))
        with self.assertRaises(Forbidden):
            self.service.require_member(channel["id"], self.bob)

    def test_unknown_channel_is_not_found(self):
        with self.assertRaises(NotFound):
            self.service.require_channel("0" * 32)

    def test_list_channels_reports_joined_state_per_user(self):
        first = self.service.create_channel("first", self.user)
        self.service.create_channel("second", self.bob)
        listed = self.service.list_channels(self.bob["id"])
        by_name = {channel["name"]: channel for channel in listed}
        self.assertEqual(by_name["first"]["joined"], 0)
        self.assertEqual(by_name["second"]["joined"], 1)
        self.assertNotEqual(first["id"], by_name["second"]["id"])


class MessageTests(ChatTestCase):
    def setUp(self):
        super().setUp()
        self.channel = self.service.create_channel("general", self.user)

    def test_sequence_increments_per_channel(self):
        first, created_first = self.service.post_message(
            self.channel["id"], "alice", "one"
        )
        second, created_second = self.service.post_message(
            self.channel["id"], "alice", "two"
        )
        self.assertTrue(created_first and created_second)
        self.assertEqual((first["seq"], second["seq"]), (1, 2))

    def test_sequences_are_independent_between_channels(self):
        other = self.service.create_channel("other", self.user)
        self.service.post_message(self.channel["id"], "alice", "a")
        message, _ = self.service.post_message(other["id"], "alice", "b")
        self.assertEqual(message["seq"], 1)

    def test_duplicate_message_id_is_idempotent(self):
        payload = {"message_id": "a" * 32}
        first, created = self.service.post_message(
            self.channel["id"], "alice", "hello", **payload
        )
        again, created_again = self.service.post_message(
            self.channel["id"], "alice", "hello", **payload
        )
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first["id"], again["id"])
        self.assertEqual(first["seq"], again["seq"])

    def test_messages_since_filters_and_orders(self):
        for index in range(5):
            self.service.post_message(self.channel["id"], "alice", f"m{index}")
        rows = self.service.messages(self.channel["id"], since=2)
        self.assertEqual([row["seq"] for row in rows], [3, 4, 5])
        self.assertEqual(rows[0]["body"], "m2")

    def test_messages_limit(self):
        for index in range(5):
            self.service.post_message(self.channel["id"], "alice", f"m{index}")
        rows = self.service.messages(self.channel["id"], limit=2)
        self.assertEqual(len(rows), 2)

    def test_body_validation(self):
        for body in ("", "   ", None, 42, "bad\x00body", "x" * 9000):
            with self.subTest(body=body):
                with self.assertRaises(BadRequest):
                    self.service.post_message(self.channel["id"], "alice", body)

    def test_invalid_message_id(self):
        with self.assertRaises(BadRequest):
            self.service.post_message(
                self.channel["id"], "alice", "hi", message_id="not-hex"
            )

    def test_multiline_body_is_allowed(self):
        message, _ = self.service.post_message(
            self.channel["id"], "alice", "line one\nline two\ttabbed"
        )
        self.assertIn("\n", message["body"])

    def test_stored_message_survives_new_service_instance(self):
        self.service.post_message(self.channel["id"], "alice", "persisted")
        second = ChatService(self.database, clock=lambda: self.now)
        rows = second.messages(self.channel["id"])
        self.assertEqual(rows[0]["body"], "persisted")


class PeerTests(ChatTestCase):
    def test_register_and_list_peers(self):
        self.service.register_peer("alice", "127.0.0.1", 9101)
        peers = self.service.peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["port"], 9101)

    def test_upsert_refreshes_last_seen(self):
        self.service.register_peer("alice", "127.0.0.1", 9101)
        self.now += 10
        self.service.register_peer("alice", "127.0.0.1", 9101)
        peers = self.service.peers()
        self.assertEqual(peers[0]["last_seen"], self.now)

    def test_stale_peers_are_hidden_then_pruned(self):
        self.service.register_peer("alice", "127.0.0.1", 9101)
        self.now += self.service.peer_ttl + 1
        self.assertEqual(self.service.peers(), [])
        self.assertEqual(self.service.prune_peers(), 1)

    def test_peers_can_exclude_one_username(self):
        self.service.register_peer("alice", "127.0.0.1", 9101)
        self.service.register_peer("bob", "127.0.0.1", 9102)
        peers = self.service.peers(exclude="alice")
        self.assertEqual([peer["username"] for peer in peers], ["bob"])

    def test_peer_address_lookup(self):
        self.service.register_peer("alice", "127.0.0.1", 9101)
        self.assertEqual(self.service.peer_address("ALICE"), ("127.0.0.1", 9101))
        self.assertIsNone(self.service.peer_address("nobody"))

    def test_invalid_peer_data(self):
        with self.assertRaises(BadRequest):
            self.service.register_peer("", "127.0.0.1", 9101)
        with self.assertRaises(BadRequest):
            self.service.register_peer("alice", "", 9101)
        with self.assertRaises(BadRequest):
            self.service.register_peer("alice", "127.0.0.1", 70000)
        with self.assertRaises(BadRequest):
            self.service.register_peer("alice", "127.0.0.1", "port")


class SchemaTests(unittest.TestCase):
    def test_chat_tables_exist(self):
        database = Database(":memory:")
        self.addCleanup(database.close)
        names = {
            row["name"]
            for row in database._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        for table in (
            "users",
            "sessions",
            "peers",
            "channels",
            "channel_members",
            "messages",
        ):
            self.assertIn(table, names)

    def test_deleting_a_channel_cascades_to_messages(self):
        database = Database(":memory:")
        self.addCleanup(database.close)
        user = database.create_user("carol", b"h", b"s", 1000, 1)
        channel = database.create_channel("c" * 32, "temp", user["id"], 1)
        database.append_message("a" * 32, channel["id"], "carol", "hi", 2)
        with database._connection:
            database._connection.execute(
                "DELETE FROM channels WHERE id = ?", (channel["id"],)
            )
        self.assertEqual(database.list_messages(channel["id"]), [])


if __name__ == "__main__":
    unittest.main()
