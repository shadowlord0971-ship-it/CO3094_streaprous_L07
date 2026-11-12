import base64
import json
import time
import unittest
from unittest import mock

from daemon.auth import AuthService
from daemon.database import Database
from daemon.errors import BadRequest
from daemon.httpadapter import HttpAdapter
from daemon.request import Request
from daemon.response import Response
from daemon.streaprous import StreapRous


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.database = Database(":memory:")
        self.addCleanup(self.database.close)
        self.app = StreapRous()
        self.service = AuthService(
            self.database,
            signing_key=b"test signing key with enough entropy",
            password_iterations=1000,
        )
        self.service.install(self.app)

        @self.app.route("/private", auth=True)
        def private(request):
            return {"username": request.user["username"]}

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

    def dispatch(self, method, path, payload=None, headers=None):
        body = b""
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request = Request().prepare(
            self._raw_request(method, path, body, request_headers),
            self.app.routes,
        )
        response = HttpAdapter(None, None, None, None, self.app.routes).dispatch(
            request
        )
        return request, response

    def register(self, username="alice", password="correct horse"):
        return self.dispatch(
            "POST",
            "/register",
            {"username": username, "password": password},
        )[1]

    @staticmethod
    def _cookie_value(response):
        cookie = next(
            value for value in response.cookies
            if value.startswith("SR_SESSION=")
        )
        return cookie.split(";", 1)[0]

    def test_register_hashes_password_and_rejects_duplicate_username(self):
        response = self.register()
        self.assertEqual(response.status_code, 201)
        user = self.database.get_user("alice")
        self.assertNotEqual(user["password_hash"], b"correct horse")
        self.assertNotEqual(user["salt"], b"")
        self.assertEqual(self.register("ALICE").status_code, 409)

    def test_register_validates_password_and_request_body(self):
        with self.assertRaises(BadRequest):
            self.register(password="short")
        self.assertIsNone(self.database.get_user("alice"))

        with self.assertRaises(BadRequest):
            self.dispatch("POST", "/register", {"username": "alice"})

    def test_login_sets_signed_http_only_session_and_csrf_token(self):
        self.register()

        _request, response = self.dispatch(
            "POST",
            "/login",
            {"username": "alice", "password": "correct horse"},
        )

        self.assertEqual(response.status_code, 200)
        cookie = self._cookie_value(response)
        self.assertIn("HttpOnly", response.cookies[0])
        self.assertIn("SameSite=Lax", response.cookies[0])
        result = json.loads(response.body)
        self.assertEqual(result["user"]["username"], "alice")
        self.assertTrue(result["csrf_token"])
        self.assertIsNotNone(self.service._session_from_cookie(
            cookie.split("=", 1)[1]
        ))

    def test_invalid_credentials_do_not_authenticate(self):
        self.register()

        response = self.dispatch(
            "POST",
            "/login",
            {"username": "alice", "password": "incorrect password"},
        )[1]

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.cookies, [])

    def test_session_authenticates_request_and_logout_revokes_it(self):
        self.register()
        _request, login_response = self.dispatch(
            "POST",
            "/login",
            {"username": "alice", "password": "correct horse"},
        )
        cookie = self._cookie_value(login_response)
        csrf_token = json.loads(login_response.body)["csrf_token"]

        request, response = self.dispatch(
            "GET",
            "/private",
            headers={"Cookie": cookie},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.user["username"], "alice")
        self.assertEqual(json.loads(response.body)["username"], "alice")

        _request, rejected = self.dispatch(
            "POST",
            "/logout",
            headers={"Cookie": cookie, "X-CSRF-Token": "wrong"},
        )
        self.assertEqual(rejected.status_code, 403)
        _request, non_ascii_rejected = self.dispatch(
            "POST",
            "/logout",
            headers={"Cookie": cookie, "X-CSRF-Token": "é" * 43},
        )
        self.assertEqual(non_ascii_rejected.status_code, 403)

        _request, logged_out = self.dispatch(
            "POST",
            "/logout",
            headers={"Cookie": cookie, "X-CSRF-Token": csrf_token},
        )
        self.assertEqual(logged_out.status_code, 200)
        self.assertTrue(any("Max-Age=0" in c for c in logged_out.cookies))

        _request, current = self.dispatch(
            "GET",
            "/api/me",
            headers={"Cookie": cookie},
        )
        self.assertEqual(current.status_code, 401)

    def test_tampered_session_cookie_is_rejected(self):
        self.register()
        _request, login_response = self.dispatch(
            "POST",
            "/login",
            {"username": "alice", "password": "correct horse"},
        )
        cookie = self._cookie_value(login_response)
        token, signature = cookie.split("=", 1)[1].split(".", 1)
        tampered_cookie = f"SR_SESSION={token}.{signature[:-1]}x"

        _request, response = self.dispatch(
            "GET",
            "/api/me",
            headers={"Cookie": tampered_cookie},
        )

        self.assertEqual(response.status_code, 401)

    def test_basic_authentication_can_access_protected_route(self):
        self.register()
        encoded = base64.b64encode(b"alice:correct horse").decode("ascii")

        request, response = self.dispatch(
            "GET",
            "/private",
            headers={"Authorization": f"Basic {encoded}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.user["username"], "alice")

    def test_install_is_idempotent(self):
        hook_count = len(self.app.routes.before_request_hooks)

        installed = self.service.install(self.app)

        self.assertIs(installed, self.service)
        self.assertEqual(len(self.app.routes.before_request_hooks), hook_count)

    def test_peer_token_round_trip(self):
        token = self.service.issue_peer_token("alice")
        self.assertEqual(self.service.verify_peer_token(token), "alice")

    def test_peer_token_rejects_tampering(self):
        token = self.service.issue_peer_token("alice")
        payload, signature = token.split(".")
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        tampered = base64.urlsafe_b64encode(
            raw.replace(b"alice", b"alicf")
        ).rstrip(b"=").decode("ascii")
        self.assertIsNone(self.service.verify_peer_token(f"{tampered}.{signature}"))
        self.assertIsNone(self.service.verify_peer_token(token + "x"))

    def test_peer_token_rejects_garbage(self):
        for value in ("", "no-dot", "a.b", None, 42):
            with self.subTest(value=value):
                self.assertIsNone(self.service.verify_peer_token(value))

    def test_peer_token_expires(self):
        token = self.service.issue_peer_token("alice", ttl=60)
        future = time.time() + 3600
        with mock.patch("daemon.auth.time.time", return_value=future):
            self.assertIsNone(self.service.verify_peer_token(token))

    def test_peer_token_is_bound_to_the_signing_key(self):
        other = AuthService(
            Database(":memory:"),
            signing_key=b"a completely different signing key!!",
            password_iterations=1000,
        )
        self.addCleanup(other.database.close)
        self.assertIsNone(other.verify_peer_token(self.service.issue_peer_token("alice")))



if __name__ == "__main__":
    unittest.main()
