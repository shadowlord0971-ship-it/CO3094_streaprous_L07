"""Tests for the UDP chat protocol codec."""

import struct
import unittest

from daemon import protocol
from daemon.protocol import Frame, ProtocolError


class HeaderTests(unittest.TestCase):
    def test_header_is_sixteen_bytes(self):
        self.assertEqual(protocol.HEADER_SIZE, 16)
        self.assertEqual(protocol.MAX_PAYLOAD, 1384)

    def test_control_frame_round_trip(self):
        frame = Frame.with_json(
            protocol.PING, {"username": "alice"}, seq=3, ack=7, window=12
        )
        decoded = protocol.decode_frame(frame.encode())
        self.assertEqual(decoded.type, protocol.PING)
        self.assertEqual(decoded.seq, 3)
        self.assertEqual(decoded.ack, 7)
        self.assertEqual(decoded.window, 12)
        self.assertEqual(decoded.json_payload(), {"username": "alice"})
        self.assertEqual(decoded.name, "PING")

    def test_empty_payload_round_trip(self):
        decoded = protocol.decode_frame(Frame(protocol.BYE, 9, 4).encode())
        self.assertEqual(decoded.payload, b"")

    def test_maximum_payload_round_trip(self):
        payload = b"x" * protocol.MAX_PAYLOAD
        decoded = protocol.decode_frame(Frame(protocol.MSG, 1, 0, 1, payload).encode())
        self.assertEqual(len(decoded.payload), protocol.MAX_PAYLOAD)

    def test_overlong_payload_is_rejected_on_encode(self):
        with self.assertRaises(ProtocolError):
            Frame(protocol.MSG, 1, 0, 1, b"x" * (protocol.MAX_PAYLOAD + 1)).encode()

    def test_short_datagram_is_rejected(self):
        with self.assertRaises(ProtocolError):
            protocol.decode_frame(b"SR\x01")

    def test_bad_magic_is_rejected(self):
        encoded = Frame(protocol.PING, 1).encode()
        with self.assertRaises(ProtocolError):
            protocol.decode_frame(b"XX" + encoded[2:])

    def test_bad_version_is_rejected(self):
        encoded = bytearray(Frame(protocol.PING, 1).encode())
        encoded[2] = 99
        with self.assertRaises(ProtocolError):
            protocol.decode_frame(bytes(encoded))

    def test_unknown_type_is_rejected(self):
        encoded = bytearray(Frame(protocol.PING, 1).encode())
        encoded[3] = 200
        with self.assertRaises(ProtocolError):
            protocol.decode_frame(bytes(encoded))

    def test_length_mismatch_is_rejected(self):
        encoded = Frame(protocol.PING, 1, payload=b"abc").encode()
        with self.assertRaises(ProtocolError):
            protocol.decode_frame(encoded[:-1])
        with self.assertRaises(ProtocolError):
            protocol.decode_frame(encoded + b"x")

    def test_non_bytes_input_is_rejected(self):
        with self.assertRaises(ProtocolError):
            protocol.decode_frame("not bytes")

    def test_json_payload_requires_an_object(self):
        frame = Frame(protocol.PING, 1, payload=b"[1,2,3]")
        with self.assertRaises(ProtocolError):
            frame.json_payload()

    def test_json_payload_rejects_invalid_utf8(self):
        frame = Frame(protocol.PING, 1, payload=b"\xff\xfe")
        with self.assertRaises(ProtocolError):
            frame.json_payload()

    def test_with_json_rejects_unserialisable_values(self):
        with self.assertRaises(ProtocolError):
            Frame.with_json(protocol.PING, {"bad": object()})

    def test_encode_rejects_out_of_range_sequence(self):
        with self.assertRaises(ProtocolError):
            Frame(protocol.PING, -1).encode()
        with self.assertRaises(ProtocolError):
            Frame(protocol.PING, 0x1_0000_0000).encode()


class EnvelopeTests(unittest.TestCase):
    def test_envelope_round_trip(self):
        envelope = protocol.message_envelope(
            channel="c" * 32,
            sender="alice",
            body="hello",
            ts=1_730_000_000,
        )
        validated = protocol.validate_envelope(envelope)
        self.assertEqual(validated["body"], "hello")
        self.assertEqual(validated["to"], "*")
        self.assertEqual(validated["ts"], 1_730_000_000)
        self.assertEqual(len(validated["id"]), 32)

    def test_envelope_defaults_are_unique(self):
        first = protocol.message_envelope(channel="a", sender="x", body="1")
        second = protocol.message_envelope(channel="a", sender="x", body="1")
        self.assertNotEqual(first["id"], second["id"])

    def test_envelope_requires_fields(self):
        with self.assertRaises(ProtocolError):
            protocol.validate_envelope({"id": "a" * 32, "channel": "c"})

    def test_envelope_rejects_non_hex_id(self):
        envelope = protocol.message_envelope(channel="c", sender="a", body="b")
        envelope["id"] = "zzzzzzzzzzzzzzzz"
        with self.assertRaises(ProtocolError):
            protocol.validate_envelope(envelope)

    def test_envelope_rejects_oversized_body(self):
        envelope = protocol.message_envelope(channel="c", sender="a", body="x")
        envelope["body"] = "x" * (protocol.MAX_BODY_BYTES + 1)
        with self.assertRaises(ProtocolError):
            protocol.validate_envelope(envelope)

    def test_envelope_requires_string_body(self):
        envelope = protocol.message_envelope(channel="c", sender="a", body="b")
        envelope["body"] = {"not": "a string"}
        with self.assertRaises(ProtocolError):
            protocol.validate_envelope(envelope)

    def test_envelope_normalises_to_field(self):
        envelope = protocol.message_envelope(channel="c", sender="a", body="b")
        envelope.pop("to")
        self.assertEqual(protocol.validate_envelope(envelope)["to"], "*")


class ConstructorTests(unittest.TestCase):
    def test_hello_frame(self):
        decoded = protocol.decode_frame(protocol.hello("alice", "127.0.0.1", 9101, "token-value").encode())
        payload = decoded.json_payload()
        self.assertEqual(decoded.type, protocol.HELLO)
        self.assertEqual(payload["username"], "alice")
        self.assertEqual(payload["port"], 9101)
        self.assertEqual(payload["token"], "token-value")

    def test_ping_frame(self):
        decoded = protocol.decode_frame(
            protocol.ping("bob", "t", ip="127.0.0.1", port=9102).encode()
        )
        payload = decoded.json_payload()
        self.assertEqual(decoded.type, protocol.PING)
        self.assertEqual(payload["username"], "bob")
        self.assertEqual(payload["ip"], "127.0.0.1")
        self.assertEqual(payload["port"], 9102)

    def test_message_frame_carries_envelope_and_token(self):
        envelope = protocol.message_envelope(channel="c", sender="a", body="hi")
        frame = Frame(
            protocol.MSG, 5, payload=protocol.encode_message(envelope, "peer-token")
        )
        decoded = protocol.decode_frame(frame.encode())
        self.assertEqual(decoded.seq, 5)
        parsed_envelope, token = protocol.decode_message(decoded.payload)
        self.assertEqual(parsed_envelope["body"], "hi")
        self.assertEqual(token, "peer-token")

    def test_message_requires_a_token(self):
        envelope = protocol.message_envelope(channel="c", sender="a", body="hi")
        with self.assertRaises(ProtocolError):
            protocol.encode_message(envelope, "")

    def test_decode_message_rejects_missing_token(self):
        with self.assertRaises(ProtocolError):
            protocol.decode_message(b'{"envelope": {"id": "a"}}')

    def test_type_names_are_stable(self):
        self.assertEqual(protocol.TYPE_NAMES[protocol.MSG], "MSG")
        self.assertEqual(protocol.frame_type_name(999), "UNKNOWN")


class HeaderLayoutTests(unittest.TestCase):
    def test_wire_layout_is_big_endian(self):
        encoded = Frame(protocol.MSG, 0x01020304, 0x05060708, 9, b"hi").encode()
        self.assertEqual(encoded[:2], b"SR")
        self.assertEqual(struct.unpack(">I", encoded[4:8])[0], 0x01020304)
        self.assertEqual(struct.unpack(">I", encoded[8:12])[0], 0x05060708)
        self.assertEqual(struct.unpack(">H", encoded[12:14])[0], 9)
        self.assertEqual(struct.unpack(">H", encoded[14:16])[0], 2)


if __name__ == "__main__":
    unittest.main()
