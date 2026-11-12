"""Account registration, password authentication, and signed sessions."""

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import time

from .database import Database
from .errors import BadRequest, UnsupportedMediaType
from .response import Response

logger = logging.getLogger(__name__)

SESSION_COOKIE = "SR_SESSION"
CSRF_HEADER = "X-CSRF-Token"
SESSION_TTL_SECONDS = 12 * 60 * 60
PASSWORD_ITERATIONS = 310_000
PASSWORD_SALT_BYTES = 16
PASSWORD_HASH_BYTES = 32
MAX_PASSWORD_BYTES = 1024
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
_SESSION_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class AuthService:
    """Authentication service backed by a :class:`Database` instance."""

    def __init__(
        self,
        database,
        *,
        signing_key=None,
        session_ttl=SESSION_TTL_SECONDS,
        cookie_secure=False,
        password_iterations=PASSWORD_ITERATIONS,
    ):
        self.database = (
            database if isinstance(database, Database) else Database(database)
        )
        if session_ttl <= 0:
            raise ValueError("session_ttl must be positive")
        if password_iterations <= 0:
            raise ValueError("password_iterations must be positive")
        self.session_ttl = int(session_ttl)
        self.cookie_secure = bool(cookie_secure)
        self.password_iterations = int(password_iterations)

        if signing_key is None:
            configured_key = os.environ.get("STREAPROUS_SESSION_SECRET")
            if configured_key:
                signing_key = configured_key.encode("utf-8")
            else:
                signing_key = secrets.token_bytes(32)
                logger.warning(
                    "STREAPROUS_SESSION_SECRET is unset; sessions will be "
                    "invalidated when this process restarts"
                )
        elif isinstance(signing_key, str):
            signing_key = signing_key.encode("utf-8")
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("session signing key must be at least 32 bytes")
        self._signing_key = signing_key
        self._dummy_salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
        self._dummy_hash = hashlib.pbkdf2_hmac(
            "sha256",
            b"not-a-real-password",
            self._dummy_salt,
            self.password_iterations,
            dklen=PASSWORD_HASH_BYTES,
        )

    @staticmethod
    def _public_user(user):
        return {
            "id": user["id"],
            "username": user["username"],
            "created_at": user["created_at"],
        }

    @staticmethod
    def _validate_username(username):
        if not isinstance(username, str):
            raise BadRequest("username must be a string")
        username = username.strip()
        if not _USERNAME_RE.fullmatch(username):
            raise BadRequest(
                "username must be 3-32 characters: letters, digits, '.', '_' or '-'"
            )
        return username

    @staticmethod
    def _validate_password(password):
        if not isinstance(password, str):
            raise BadRequest("password must be a string")
        try:
            encoded = password.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BadRequest("password is not valid UTF-8") from exc
        if len(encoded) < 8:
            raise BadRequest("password must be at least 8 bytes")
        if len(encoded) > MAX_PASSWORD_BYTES:
            raise BadRequest("password is too long")
        return encoded

    def register(self, username, password):
        username = self._validate_username(username)
        password_bytes = self._validate_password(password)
        salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            self.password_iterations,
            dklen=PASSWORD_HASH_BYTES,
        )
        return self.database.create_user(
            username,
            password_hash,
            salt,
            self.password_iterations,
            int(time.time()),
        )

    def authenticate(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        try:
            username = self._validate_username(username)
            password_bytes = self._validate_password(password)
        except BadRequest:
            return None

        user = self.database.get_user(username)
        salt = user["salt"] if user else self._dummy_salt
        iterations = user["iterations"] if user else self.password_iterations
        expected = user["password_hash"] if user else self._dummy_hash
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            iterations,
            dklen=PASSWORD_HASH_BYTES,
        )
        if user is None or not hmac.compare_digest(actual, expected):
            return None
        return self._public_user(user)

    def _token_hash(self, token):
        return hashlib.sha256(token.encode("ascii")).digest()

    def _signature(self, purpose, value):
        message = purpose + b":" + value.encode("ascii")
        return _b64url(hmac.new(self._signing_key, message, hashlib.sha256).digest())

    def issue_peer_token(self, username, ttl=3600):
        """Return a signed token proving ``username`` to another peer."""
        if not isinstance(username, str) or not username:
            raise ValueError("username is required")
        ttl = int(ttl)
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        expires_at = int(time.time()) + ttl
        payload = f"{username}|{expires_at}".encode("utf-8")
        signature = hmac.new(
            self._signing_key, b"peer:" + payload, hashlib.sha256
        ).digest()
        return _b64url(payload) + "." + _b64url(signature)

    def verify_peer_token(self, token):
        """Return the username for a valid token, otherwise ``None``."""
        if not isinstance(token, str) or token.count(".") != 1:
            return None
        encoded_payload, encoded_signature = token.split(".")
        try:
            payload = base64.urlsafe_b64decode(
                encoded_payload + "=" * (-len(encoded_payload) % 4)
            )
            signature = base64.urlsafe_b64decode(
                encoded_signature + "=" * (-len(encoded_signature) % 4)
            )
        except (ValueError, TypeError):
            return None
        expected = hmac.new(
            self._signing_key, b"peer:" + payload, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        username, _separator, expires_at = payload.decode("utf-8", "replace").rpartition("|")
        try:
            expires_at = int(expires_at)
        except ValueError:
            return None
        if not username or expires_at < int(time.time()):
            return None
        return username


    def _csrf_for_token(self, token):
        return self._signature(b"csrf", token)

    def _create_session(self, user):
        token = secrets.token_urlsafe(32)
        token_hash = self._token_hash(token)
        now = int(time.time())
        expires_at = now + self.session_ttl
        self.database.delete_expired_sessions(now)
        self.database.create_session(token_hash, user["id"], now, expires_at)
        cookie = f"{token}.{self._signature(b'session', token)}"
        csrf_token = self._csrf_for_token(token)
        return cookie, csrf_token, expires_at

    def _session_from_cookie(self, cookie_value):
        if not isinstance(cookie_value, str):
            return None
        token, separator, supplied_signature = cookie_value.partition(".")
        if (
            not separator
            or not _SESSION_TOKEN_RE.fullmatch(token)
            or not _SIGNATURE_RE.fullmatch(supplied_signature)
        ):
            return None
        expected_signature = self._signature(b"session", token)
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        try:
            token_hash = self._token_hash(token)
        except UnicodeEncodeError:
            return None
        user = self.database.get_session_user(token_hash, int(time.time()))
        if user is None:
            return None
        return {
            "user": self._public_user(user),
            "token": token,
            "token_hash": token_hash,
            "csrf_token": self._csrf_for_token(token),
        }

    def authenticate_request(self, request):
        session = self._session_from_cookie(
            (getattr(request, "cookies", None) or {}).get(SESSION_COOKIE)
        )
        if session is not None:
            return session["user"]

        credentials = getattr(request, "auth", None)
        if credentials:
            return self.authenticate(*credentials)
        return None

    def _credentials_from_request(self, request):
        if request.is_json:
            payload = request.json
        elif request.mimetype in ("", "application/x-www-form-urlencoded"):
            payload = {
                name: values[-1] if values else ""
                for name, values in request.form.items()
            }
        else:
            raise UnsupportedMediaType(
                "Use application/json or application/x-www-form-urlencoded"
            )
        if not isinstance(payload, dict):
            raise BadRequest("request body must be an object")
        return payload.get("username"), payload.get("password")

    def _set_session_cookie(self, response, cookie, expires_at):
        response.set_cookie(
            SESSION_COOKIE,
            cookie,
            max_age=max(0, expires_at - int(time.time())),
            path="/",
            http_only=True,
            secure=self.cookie_secure,
            same_site="Lax",
        )

    def install(self, app):
        """Register auth routes and a request hook on a StreapRous app."""
        existing = getattr(app, "_streaprous_auth_service", None)
        if existing is not None:
            return existing

        @app.before_request
        def load_authenticated_user(request):
            request.user = self.authenticate_request(request)
            return None

        @app.route("/register", methods=["POST"])
        def register(request):
            username, password = self._credentials_from_request(request)
            try:
                user = self.register(username, password)
            except sqlite3.IntegrityError:
                return Response().json(
                    {"error": "username is already registered"},
                    status=409,
                )
            return Response().json(
                {"user": self._public_user(user)},
                status=201,
            )

        @app.route("/login", methods=["POST"])
        def login(request):
            username, password = self._credentials_from_request(request)
            user = self.authenticate(username, password)
            if user is None:
                return Response().json(
                    {"error": "invalid username or password"},
                    status=401,
                )
            stored_user = self.database.get_user(user["username"])
            cookie, csrf_token, expires_at = self._create_session(stored_user)
            response = Response().json(
                {"user": user, "csrf_token": csrf_token}
            )
            self._set_session_cookie(response, cookie, expires_at)
            return response

        @app.route("/logout", methods=["POST"])
        def logout(request):
            cookie_value = (request.cookies or {}).get(SESSION_COOKIE)
            session = self._session_from_cookie(cookie_value)
            if session is not None:
                supplied_csrf = request.headers.get(CSRF_HEADER, "")
                if (
                    not isinstance(supplied_csrf, str)
                    or not _SIGNATURE_RE.fullmatch(supplied_csrf)
                    or not hmac.compare_digest(
                        supplied_csrf, session["csrf_token"]
                    )
                ):
                    return Response().json(
                        {"error": "valid CSRF token required"},
                        status=403,
                    )
                self.database.delete_session(session["token_hash"])

            response = Response().json({"ok": True})
            response.delete_cookie(SESSION_COOKIE, path="/")
            return response

        @app.route("/api/me", methods=["GET"])
        def current_user(request):
            if request.user is None:
                return Response().json(
                    {"error": "authentication required"},
                    status=401,
                )
            result = {"user": request.user}
            session = self._session_from_cookie(
                (request.cookies or {}).get(SESSION_COOKIE)
            )
            if session is not None:
                result["csrf_token"] = session["csrf_token"]
            return Response().json(result)

        app._streaprous_auth_service = self
        return self


def install_auth(
    app,
    database_path=None,
    *,
    signing_key=None,
    cookie_secure=None,
    password_iterations=None,
):
    """Install account endpoints on an app using environment-based settings."""
    existing = getattr(app, "_streaprous_auth_service", None)
    if existing is not None:
        return existing
    database_path = database_path or os.environ.get(
        "STREAPROUS_DB_PATH",
        os.path.join("data", "streaprous.sqlite3"),
    )
    if cookie_secure is None:
        cookie_secure = os.environ.get(
            "STREAPROUS_COOKIE_SECURE", ""
        ).strip().lower() in ("1", "true", "yes", "on")
    options = {
        "signing_key": signing_key,
        "cookie_secure": cookie_secure,
    }
    if password_iterations is not None:
        options["password_iterations"] = int(password_iterations)
    service = AuthService(database_path, **options)
    return service.install(app)

