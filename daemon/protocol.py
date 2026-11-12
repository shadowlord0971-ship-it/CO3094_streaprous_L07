"""UDP chat framing: 16-byte header, JSON control payloads.

Header (big endian): magic "SR", version, type, seq, ack, window, length.
"""

import json
import struct
import time
import uuid
from dataclasses import dataclass

MAGIC = b"SR"
VERSION = 1
HEADER = struct.Struct(">2sBBIIHH")
HEADER_SIZE = HEADER.size
MAX_DATAGRAM = 1400
MAX_PAYLOAD = MAX_DATAGRAM - HEADER_SIZE
DEFAULT_WINDOW = 32
MAX_BODY_BYTES = 8 * 1024

# Frame types.
HELLO = 1
HELLO_ACK = 2
PING = 3
PONG = 4
AUTH_ERR = 7
MSG = 8
MSG_ACK = 9
BYE = 14

TYPE_NAMES = {
    HELLO: "HELLO",
    HELLO_ACK: "HELLO_ACK",
    PING: "PING",
    PONG: "PONG",
    AUTH_ERR: "AUTH_ERR",
    MSG: "MSG",
    MSG_ACK: "MSG_ACK",
    BYE: "BYE",
}

class ProtocolError(ValueError):
    """Raised when a datagram cannot be decoded."""


def frame_type_name(frame_type):
    """Return the symbolic name for a frame type, or ``"UNKNOWN"``."""
    return TYPE_NAMES.get(frame_type, "UNKNOWN")

@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded protocol frame."""

    type: int
    seq: int = 0
    ack: int = 0
    window: int = DEFAULT_WINDOW
    payload: bytes = b""

    @property
    def name(self):
        return frame_type_name(self.type)

    def encode(self):
        if len(self.payload) > MAX_PAYLOAD:
            raise ProtocolError(
                f"payload of {len(self.payload)} bytes exceeds {MAX_PAYLOAD}"
            )
        if not 0 <= self.seq <= 0xFFFFFFFF:
            raise ProtocolError("seq out of range")
        if not 0 <= self.ack <= 0xFFFFFFFF:
            raise ProtocolError("ack out of range")
        return HEADER.pack(
            MAGIC,
            VERSION,
            self.type,
            self.seq,
            self.ack,
            max(0, min(int(self.window), 0xFFFF)),
            len(self.payload),
        ) + bytes(self.payload)

    def json_payload(self):
        try:
            value = json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProtocolError("payload is not valid JSON") from exc
        if not isinstance(value, dict):
            raise ProtocolError("JSON payload must be an object")
        return value

    @classmethod
    def with_json(cls, frame_type, value, *, seq=0, ack=0, window=DEFAULT_WINDOW):
        try:
            payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ProtocolError("payload is not JSON serialisable") from exc
        return cls(frame_type, seq, ack, window, payload)

def decode_frame(datagram):
    """Decode one datagram into a :class:`Frame`.

    Raises :class:`ProtocolError` for anything that is not a well-formed,
    currently supported frame.  Callers on a socket loop should catch it and
    count the datagram as malformed instead of terminating.
    """
    if not isinstance(datagram, (bytes, bytearray, memoryview)):
        raise ProtocolError("datagram must be bytes-like")
    data = bytes(datagram)
    if len(data) < HEADER_SIZE:
        raise ProtocolError("datagram shorter than the protocol header")

    magic, version, frame_type, seq, ack, window, length = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ProtocolError("bad magic")
    if version != VERSION:
        raise ProtocolError(f"unsupported protocol version {version}")
    if frame_type not in TYPE_NAMES:
        raise ProtocolError(f"unknown frame type {frame_type}")
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"payload length {length} exceeds {MAX_PAYLOAD}")
    if len(data) != HEADER_SIZE + length:
        raise ProtocolError(
            f"length field {length} does not match datagram size {len(data)}"
        )
    return Frame(frame_type, seq, ack, window, data[HEADER_SIZE:])


def new_message_id():
    """Return a fresh UUID4 hex identifier used as the dedupe key."""
    return uuid.uuid4().hex


def message_envelope(
    *,
    channel,
    sender,
    body,
    message_id=None,
    recipient="*",
    ts=None,
):
    """Build the JSON envelope carried by a ``MSG`` frame."""
    envelope = {
        "v": VERSION,
        "id": message_id or new_message_id(),
        "channel": channel,
        "from": sender,
        "to": recipient,
        "body": body,
        "ts": int(ts if ts is not None else time.time()),
    }
    return envelope


def validate_envelope(value):
    """Validate and normalise a message envelope.

    Returns a dict with exactly the documented keys.  Raises
    :class:`ProtocolError` when a required field is missing or invalid.
    """
    if not isinstance(value, dict):
        raise ProtocolError("envelope must be a JSON object")
    required = ("id", "channel", "from", "body", "ts")
    missing = [key for key in required if key not in value]
    if missing:
        raise ProtocolError("missing envelope field(s): " + ", ".join(missing))

    message_id = value["id"]
    if not isinstance(message_id, str) or not 8 <= len(message_id) <= 64:
        raise ProtocolError("envelope id must be a hex string")
    try:
        int(message_id, 16)
    except ValueError as exc:
        raise ProtocolError("envelope id must be hexadecimal") from exc

    channel = value["channel"]
    if not isinstance(channel, str) or not 1 <= len(channel) <= 64:
        raise ProtocolError("envelope channel must be a non-empty string")

    sender = value["from"]
    if not isinstance(sender, str) or not 1 <= len(sender) <= 64:
        raise ProtocolError("envelope from must be a non-empty string")

    body = value["body"]
    if not isinstance(body, str):
        raise ProtocolError("envelope body must be a string")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ProtocolError(f"envelope body exceeds {MAX_BODY_BYTES} bytes")

    try:
        ts = int(value["ts"])
    except (TypeError, ValueError) as exc:
        raise ProtocolError("envelope ts must be an integer") from exc

    recipient = value.get("to", "*")
    if not isinstance(recipient, str) or not recipient:
        raise ProtocolError("envelope to must be a non-empty string")

    return {
        "id": message_id,
        "channel": channel,
        "from": sender,
        "to": recipient,
        "body": body,
        "ts": ts,
    }


def hello(username, ip, port, token, *, seq=0, window=DEFAULT_WINDOW):
    return Frame.with_json(
        HELLO,
        {"username": username, "ip": ip, "port": int(port), "token": token},
        seq=seq,
        window=window,
    )


def ping(username, token, *, ip=None, port=None):
    payload = {"username": username, "token": token}
    if ip:
        payload["ip"] = ip
    if port:
        payload["port"] = int(port)
    return Frame.with_json(PING, payload)


def encode_message(envelope, token):
    """Encode a ``MSG`` payload: the envelope plus the sender's peer token."""
    if not isinstance(token, str) or not token:
        raise ProtocolError("a peer token is required for a message")
    return json.dumps(
        {"envelope": envelope, "token": token}, separators=(",", ":")
    ).encode("utf-8")


def decode_message(payload):
    """Return ``(envelope, token)`` from a ``MSG`` payload."""
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("message payload is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("message payload must be an object")
    token = value.get("token")
    if not isinstance(token, str) or not token:
        raise ProtocolError("message payload is missing the peer token")
    return validate_envelope(value.get("envelope")), token


__all__ = [
    "AUTH_ERR",
    "BYE",
    "DEFAULT_WINDOW",
    "Frame",
    "HEADER",
    "HEADER_SIZE",
    "HELLO",
    "HELLO_ACK",
    "MAX_BODY_BYTES",
    "MAX_DATAGRAM",
    "MAX_PAYLOAD",
    "MSG",
    "MSG_ACK",
    "PING",
    "PONG",
    "ProtocolError",
    "TYPE_NAMES",
    "VERSION",
    "decode_frame",
    "decode_message",
    "encode_message",
    "frame_type_name",
    "hello",
    "message_envelope",
    "new_message_id",
    "ping",
    "validate_envelope",
]
