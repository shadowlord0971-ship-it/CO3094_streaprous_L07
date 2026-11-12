"""Chat domain service: channels, membership, messages and peering."""

import re
import time
import uuid

from . import protocol
from .errors import BadRequest, Forbidden, NotFound

CHANNEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$")
MESSAGE_ID_RE = re.compile(r"^[0-9a-f]{8,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
DEFAULT_PEER_TTL = 20


class ChatService:
    """Application logic shared by the HTTP API and the peer node."""

    def __init__(self, database, *, clock=time.time, peer_ttl=DEFAULT_PEER_TTL):
        self.database = database
        self.peer_ttl = int(peer_ttl)
        self._clock = clock

    def create_channel(self, name, owner, *, is_private=False):
        if not isinstance(name, str):
            raise BadRequest("channel name must be a string")
        name = name.strip()
        if not CHANNEL_NAME_RE.fullmatch(name):
            raise BadRequest(
                "channel name must be 1-32 characters: letters, digits, "
                "space, '.', '_' or '-'"
            )
        if self.database.get_channel_by_name(name) is not None:
            raise ValueError("channel already exists")

        channel_id = uuid.uuid4().hex
        channel = self.database.create_channel(
            channel_id,
            name,
            owner["id"],
            int(self._clock()),
            int(bool(is_private)),
        )
        self.database.add_channel_member(channel_id, owner["id"], int(self._clock()))
        channel["member_count"] = 1
        channel["joined"] = 1
        return channel

    def list_channels(self, user_id):
        return self.database.list_channels(user_id)

    def require_channel(self, channel_id):
        channel = self.database.get_channel(channel_id)
        if channel is None:
            raise NotFound("channel not found")
        return channel

    def join(self, channel_id, user):
        self.require_channel(channel_id)
        return self.database.add_channel_member(
            channel_id, user["id"], int(self._clock())
        )

    def leave(self, channel_id, user):
        self.require_channel(channel_id)
        return self.database.remove_channel_member(channel_id, user["id"])

    def require_member(self, channel_id, user):
        self.require_channel(channel_id)
        if not self.database.is_channel_member(channel_id, user["id"]):
            raise Forbidden("join the channel before using it")

    @staticmethod
    def validate_body(body):
        if not isinstance(body, str):
            raise BadRequest("message body must be a string")
        if not body.strip():
            raise BadRequest("message body must not be empty")
        if len(body.encode("utf-8")) > protocol.MAX_BODY_BYTES:
            raise BadRequest(
                f"message body must be at most {protocol.MAX_BODY_BYTES} bytes"
            )
        if _CONTROL_RE.search(body):
            raise BadRequest("message body contains control characters")
        return body

    def post_message(self, channel_id, sender, body, *, message_id=None, ts=None):
        """Return ``(message, created)``; ``created`` is False on duplicate id."""
        self.validate_body(body)
        if message_id is None:
            message_id = protocol.new_message_id()
        elif not MESSAGE_ID_RE.fullmatch(str(message_id)):
            raise BadRequest("message id must be a hex string")

        existing = self.database.get_message(message_id)
        if existing is not None:
            return existing, False

        message = self.database.append_message(
            message_id,
            channel_id,
            sender,
            body,
            int(ts if ts is not None else self._clock()),
        )
        return message, True

    def messages(self, channel_id, since=0, limit=100):
        if since < 0:
            raise BadRequest("since must not be negative")
        limit = max(1, min(int(limit), 500))
        return self.database.list_messages(channel_id, since, limit)

    def register_peer(self, username, ip, port):
        if not isinstance(username, str) or not username.strip():
            raise BadRequest("peer username must be a non-empty string")
        if not isinstance(ip, str) or not ip:
            raise BadRequest("peer ip must be a non-empty string")
        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise BadRequest("peer port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise BadRequest("peer port must be between 1 and 65535")
        return self.database.upsert_peer(
            username.strip(), ip, port, int(self._clock())
        )

    def peers(self, *, exclude=None):
        not_before = self._clock() - self.peer_ttl
        return self.database.list_peers(not_before, exclude_username=exclude)

    def prune_peers(self):
        return self.database.expire_peers(self._clock() - self.peer_ttl)

    def peer_address(self, username):
        for peer in self.peers():
            if peer["username"].lower() == str(username).lower():
                return peer["ip"], int(peer["port"])
        return None
