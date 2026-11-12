"""Tests for the chat HTTP API."""

import base64
import json
import unittest

from apps.chatapp import build_chatapp
from daemon.errors import HTTPError
from daemon.httpadapter import HttpAdapter
from daemon.request import Request


class ChatApiTests(unittest.TestCase):
    def setUp(self):
        self.app = build_chatapp(
            mode="local", db_path=":memory:", password_iterations=1000
        )
        self.addCleanup(self._close_database)
        self.auth = self.app._streaprous_auth
        self.auth.register("alice", "correct horse")
        self.auth.register("bob", "battery staple")

    def _close_database(self):
        self.auth.database.close()

    @staticmethod
    def _raw_request(method, path, body=b"", headers=None):
        headers = dict(headers or {})
        headers.setdefault("Host", "localhost")
        if body:
            headers.setdefault("Content-Length", str(len(body)))
        header_bytes = "".join(
            f"{name}: {value}\r\n" for name, value in headers.items()
        ).encode("iso-8859-1")
        return (
            f"{method} {path} HTTP/1.1\r\n".encode("ascii")
            + header_bytes
            + b"\r\n"
            + body
        )

    @staticmethod
    def _basic(username, password):
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def dispatch(self, method, path, payload=None, user=None):
        body = b""
        headers = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if user is not None:
            headers.update(self._basic(*user))
        request = Request().prepare(
            self._raw_request(method, path, body, headers), self.app.routes
        )
        adapter = HttpAdapter(None, None, None, None, self.app.routes)
        try:
            response = adapter.dispatch(request)
        except HTTPError as exc:
            response = adapter._error_response(exc)
        return request, response

    def payload(self, response):
        return json.loads(response.body.decode("utf-8"))

    def test_status_is_public(self):
        _request, response = self.dispatch("GET", "/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.payload(response)["mode"], "local")

    def test_anonymous_access_is_rejected(self):
        _request, response = self.dispatch("GET", "/api/channels")
        self.assertEqual(response.status_code, 401)

    def test_create_and_list_channels(self):
        _request, response = self.dispatch(
            "POST",
            "/api/channels",
            {"name": "general"},
            user=("alice", "correct horse"),
        )
        self.assertEqual(response.status_code, 201)
        channel = self.payload(response)["channel"]
        self.assertEqual(channel["name"], "general")

        _request, response = self.dispatch(
            "GET", "/api/channels", user=("alice", "correct horse")
        )
        listed = self.payload(response)["channels"]
        self.assertEqual([item["name"] for item in listed], ["general"])
        self.assertEqual(listed[0]["joined"], 1)

    def test_duplicate_channel_returns_conflict(self):
        self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("alice", "correct horse")
        )
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("bob", "battery staple")
        )
        self.assertEqual(response.status_code, 409)

    def test_invalid_channel_name_returns_bad_request(self):
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": ""}, user=("alice", "correct horse")
        )
        self.assertEqual(response.status_code, 400)

    def test_membership_is_required_for_messages(self):
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("alice", "correct horse")
        )
        channel_id = self.payload(response)["channel"]["id"]

        _request, response = self.dispatch(
            "GET",
            f"/api/channels/{channel_id}/messages",
            user=("bob", "battery staple"),
        )
        self.assertEqual(response.status_code, 403)

        _request, response = self.dispatch(
            "POST",
            f"/api/channels/{channel_id}/join",
            user=("bob", "battery staple"),
        )
        self.assertEqual(response.status_code, 204)

    def test_post_and_read_messages_with_since(self):
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("alice", "correct horse")
        )
        channel_id = self.payload(response)["channel"]["id"]

        for body in ("one", "two", "three"):
            _request, response = self.dispatch(
                "POST",
                f"/api/channels/{channel_id}/messages",
                {"body": body},
                user=("alice", "correct horse"),
            )
            self.assertEqual(response.status_code, 201)

        _request, response = self.dispatch(
            "GET",
            f"/api/channels/{channel_id}/messages?since=0",
            user=("alice", "correct horse"),
        )
        data = self.payload(response)
        self.assertEqual([message["body"] for message in data["messages"]],
                         ["one", "two", "three"])
        self.assertEqual(data["next_since"], 3)

        _request, response = self.dispatch(
            "GET",
            f"/api/channels/{channel_id}/messages?since=2",
            user=("alice", "correct horse"),
        )
        data = self.payload(response)
        self.assertEqual([message["body"] for message in data["messages"]], ["three"])

    def test_post_message_records_request_user(self):
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("alice", "correct horse")
        )
        channel_id = self.payload(response)["channel"]["id"]
        self.dispatch(
            "POST",
            f"/api/channels/{channel_id}/join",
            user=("bob", "battery staple"),
        )
        _request, response = self.dispatch(
            "POST",
            f"/api/channels/{channel_id}/messages",
            {"body": "from bob"},
            user=("bob", "battery staple"),
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.payload(response)["message"]["sender"], "bob")

    def test_empty_body_is_rejected(self):
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("alice", "correct horse")
        )
        channel_id = self.payload(response)["channel"]["id"]
        _request, response = self.dispatch(
            "POST",
            f"/api/channels/{channel_id}/messages",
            {"body": "   "},
            user=("alice", "correct horse"),
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_channel_returns_not_found(self):
        _request, response = self.dispatch(
            "GET",
            "/api/channels/" + "0" * 32 + "/messages",
            user=("alice", "correct horse"),
        )
        self.assertEqual(response.status_code, 404)

    def test_client_id_makes_posting_idempotent(self):
        _request, response = self.dispatch(
            "POST", "/api/channels", {"name": "general"}, user=("alice", "correct horse")
        )
        channel_id = self.payload(response)["channel"]["id"]
        client_id = "f" * 32
        payload = {"body": "only once", "client_id": client_id}
        for _ in range(2):
            _request, response = self.dispatch(
                "POST",
                f"/api/channels/{channel_id}/messages",
                payload,
                user=("alice", "correct horse"),
            )
        _request, response = self.dispatch(
            "GET",
            f"/api/channels/{channel_id}/messages",
            user=("alice", "correct horse"),
        )
        self.assertEqual(len(self.payload(response)["messages"]), 1)

    def test_peers_endpoint_is_empty_in_local_mode(self):
        _request, response = self.dispatch(
            "GET", "/api/peers", user=("alice", "correct horse")
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.payload(response)["peers"], [])


if __name__ == "__main__":
    unittest.main()
