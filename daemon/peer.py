"""Peer node: discovery, heartbeat and message delivery over UDP."""

import logging
import socket
import sqlite3
import threading
import time
from collections import deque

from . import protocol
from .udp_transport import DEFAULT_CAPACITY, DEFAULT_RTO, ReliableChannel, UdpNode

logger = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 5.0
TICK_SECONDS = 0.05


def _detect_local_ip():
    """Best-effort local IPv4 address without third-party packages."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


class PeerNode:
    """Background UDP peer with heartbeat, retransmission and relay support."""

    def __init__(
        self,
        chat,
        *,
        username,
        token,
        verifier,
        role="peer",
        listen_ip="0.0.0.0",
        udp_port=0,
        public_ip=None,
        tracker=None,
        heartbeat=HEARTBEAT_SECONDS,
        tick=TICK_SECONDS,
        capacity=DEFAULT_CAPACITY,
        rto=DEFAULT_RTO,
        cipher=None,
    ):
        if role not in ("peer", "tracker"):
            raise ValueError("role must be 'peer' or 'tracker'")
        self.chat = chat
        self.username = username
        self.token = token
        self.verifier = verifier
        self.role = role
        self.cipher = cipher
        self.tracker = tuple(tracker) if tracker else None
        self.heartbeat_seconds = float(heartbeat)
        self.tick_seconds = float(tick)
        self.capacity = int(capacity)
        self.rto = float(rto)

        self.node = UdpNode(self._on_frame, listen_ip, udp_port)
        if public_ip:
            self.public_ip = public_ip
        elif listen_ip in ("0.0.0.0", "::", ""):
            self.public_ip = _detect_local_ip()
        else:
            self.public_ip = listen_ip
        self.public_port = int(udp_port or self.node.port)
        self.address = (self.public_ip, self.public_port)

        self._channels = {}
        self._outbox = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads = []
        self.started = False
        self.stats = {
            "hellos": 0,
            "pings": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "duplicates": 0,
            "rejected": 0,
            "relayed": 0,
            "malformed": 0,
        }

    def start(self):
        if self.started:
            return self
        self.node.start()
        self.started = True
        if self.tracker is not None:
            self.send_hello()
        self._spawn(self._tick_loop, "peer-tick")
        if self.tracker is not None and self.role == "peer":
            self._spawn(self._heartbeat_loop, "peer-heartbeat")
        return self

    def stop(self, timeout=3.0):
        self._stop.set()
        self.node.stop(timeout)
        for thread in self._threads:
            thread.join(timeout)
        self._threads.clear()
        self.started = False

    def _spawn(self, target, name):
        thread = threading.Thread(target=target, name=f"{name}-{self.username}", daemon=True)
        thread.start()
        self._threads.append(thread)

    def _tick_loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("peer tick failed")
            self._stop.wait(self.tick_seconds)

    def _heartbeat_loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.heartbeat_seconds)
            if self._stop.is_set():
                break
            try:
                self.send_ping()
            except Exception:
                logger.exception("heartbeat failed")

    def tick(self):
        now = time.monotonic()
        for address, channel in list(self._channels.items()):
            for frame in channel.poll(now):
                self._send(frame, address)
            if channel.dead:
                logger.warning("peer %s stopped responding", address)
                with self._lock:
                    self._channels.pop(address, None)
        for address in list(self._outbox):
            self._flush(address)
        self.chat.prune_peers()

    def _flush(self, address):
        with self._lock:
            channel = self._channel(address)
            queue = self._outbox.get(address)
            if queue is None:
                return
            while queue:
                frame_type, payload = queue[0]
                frame = channel.queue(frame_type, payload)
                if frame is None:
                    break
                queue.popleft()
                self._send(frame, address)
                self.stats["messages_sent"] += 1
            if not queue:
                self._outbox.pop(address, None)

    def _send(self, frame, address):
        try:
            self.node.send(frame, address)
        except OSError:
            logger.warning("failed to send to %s", address)

    def _channel(self, address):
        channel = self._channels.get(address)
        if channel is None:
            channel = ReliableChannel(
                address, capacity=self.capacity, rto=self.rto
            )
            self._channels[address] = channel
        return channel

    def _enqueue(self, address, payload):
        with self._lock:
            self._outbox.setdefault(address, deque()).append(
                (protocol.MSG, payload)
            )
        self._flush(address)

    def send_hello(self):
        if self.tracker is None:
            return
        frame = protocol.hello(
            self.username, self.public_ip, self.public_port, self.token
        )
        self._send(frame, self.tracker)

    def send_ping(self):
        if self.tracker is None:
            return
        self._send(
            protocol.ping(
                self.username, self.token, ip=self.public_ip, port=self.public_port
            ),
            self.tracker,
        )

    def _broadcast_envelope(self, envelope):
        targets = self.chat.peers(exclude=self.username)
        if not targets and self.tracker is not None:
            self._relay(envelope)
            return 0
        payload = self._encode_payload(envelope)
        for peer in targets:
            self._enqueue((peer["ip"], int(peer["port"])), payload)
        return len(targets)

    def _relay(self, envelope):
        if self.tracker is None:
            return
        payload = self._encode_payload(envelope)
        self._enqueue(self.tracker, payload)
        self.stats["relayed"] += 1

    def broadcast(self, channel_id, body, *, message_id=None, sender=None):
        """Store a message locally and fan it out to every known peer."""
        sender = sender or self.username
        if sender != self.username:
            raise PermissionError("this node can only send as its own user")
        message, created = self.chat.post_message(
            channel_id, sender, body, message_id=message_id
        )
        if created:
            envelope = self._envelope(message)
            self._broadcast_envelope(envelope)
        return message

    def send_direct(self, channel_id, recipient, body, *, message_id=None, sender=None):
        """Store and deliver a message addressed to one username."""
        sender = sender or self.username
        if sender != self.username:
            raise PermissionError("this node can only send as its own user")
        message, created = self.chat.post_message(
            channel_id, sender, body, message_id=message_id
        )
        if not created:
            return message
        address = self.chat.peer_address(recipient)
        envelope = self._envelope(message, recipient=recipient)
        if address is None:
            self._relay(envelope)
        else:
            self._enqueue(address, self._encode_payload(envelope))
        return message

    @staticmethod
    def _envelope(message, recipient="*"):
        return {
            "v": protocol.VERSION,
            "id": message["id"],
            "channel": message["channel_id"],
            "from": message["sender"],
            "to": recipient,
            "body": message["body"],
            "ts": message["created_at"],
        }

    def _encode_payload(self, envelope):
        data = protocol.encode_message(envelope, self.token)
        if self.cipher is not None:
            data = self.cipher.seal(data)
        return data

    def _decode_payload(self, payload):
        if self.cipher is not None:
            payload = self.cipher.open(payload)
        return protocol.decode_message(payload)

    def _on_frame(self, frame, address):
        if address == self.node.address:
            return
        if frame.seq:
            with self._lock:
                channel = self._channel(address)
            delivered = channel.receive(frame)
            self._send(channel.acknowledgement(), address)
            for inner in delivered:
                self._dispatch(inner, address)
            return
        if frame.type == protocol.MSG_ACK:
            with self._lock:
                channel = self._channels.get(address)
            if channel is not None:
                channel.receive(frame)
            return
        self._dispatch(frame, address)

    def _dispatch(self, frame, address):
        handler = {
            protocol.HELLO: self._handle_hello,
            protocol.PING: self._handle_ping,
            protocol.HELLO_ACK: self._handle_peer_list,
            protocol.PONG: self._handle_peer_list,
            protocol.MSG: self._handle_message,
            protocol.BYE: self._handle_bye,
            protocol.AUTH_ERR: self._handle_auth_error,
        }.get(frame.type)
        if handler is None:
            return
        try:
            handler(frame, address)
        except ValueError:
            self.stats["malformed"] += 1
        except Exception:
            logger.exception("failed to handle %s from %s", frame.name, address)

    def _authenticate(self, token):
        username = self.verifier(token) if token else None
        if not username:
            self.stats["rejected"] += 1
        return username

    def _handle_hello(self, frame, address):
        payload = frame.json_payload()
        username = self._authenticate(payload.get("token"))
        if username is None:
            self._send(protocol.Frame.with_json(protocol.AUTH_ERR, {"error": "bad token"}), address)
            return
        if payload.get("username") != username:
            self.stats["rejected"] += 1
            return
        ip = payload.get("ip") or address[0]
        port = payload.get("port")
        self.chat.register_peer(username, str(ip), port)
        self.stats["hellos"] += 1
        self._send(self._peer_list_frame(protocol.HELLO_ACK), address)

    def _handle_ping(self, frame, address):
        payload = frame.json_payload()
        username = self._authenticate(payload.get("token"))
        if username is None:
            return
        # Prefer the advertised address: the source address is often 127.0.0.1
        # for a local send and would create a second row for the same peer.
        ip = payload.get("ip") or address[0]
        port = payload.get("port") or self._port_for(username)
        if port:
            self.chat.register_peer(username, str(ip), port)
        self.stats["pings"] += 1
        self._send(self._peer_list_frame(protocol.PONG), address)

    def _port_for(self, username):
        for peer in self.chat.peers():
            if peer["username"].lower() == str(username).lower():
                return int(peer["port"])
        return 0

    def _peer_list_frame(self, frame_type):
        peers = [
            {"username": peer["username"], "ip": peer["ip"], "port": peer["port"]}
            for peer in self.chat.peers(exclude=self.username)
        ]
        return protocol.Frame.with_json(frame_type, {"peers": peers})

    def _handle_peer_list(self, frame, address):
        payload = frame.json_payload()
        for peer in payload.get("peers") or []:
            if not isinstance(peer, dict):
                continue
            username = peer.get("username")
            if not username or username.lower() == self.username.lower():
                continue
            try:
                self.chat.register_peer(username, peer.get("ip", ""), peer.get("port"))
            except Exception:
                continue

    def _handle_message(self, frame, address):
        envelope, token = self._decode_payload(frame.payload)
        username = self._authenticate(token)
        if username is None:
            return
        if envelope["from"].lower() != username.lower():
            self.stats["rejected"] += 1
            return
        channel = self.chat.database.get_channel(envelope["channel"])
        if channel is None:
            # The sender's channel id is authoritative; mirror it locally so
            # the message has a home. Local users can join it afterwards.
            try:
                self.chat.database.create_channel(
                    envelope["channel"],
                    f"channel-{envelope['channel'][:8]}",
                    None,
                    int(envelope["ts"]),
                )
            except sqlite3.IntegrityError:
                pass
        _message, created = self.chat.post_message(
            envelope["channel"],
            envelope["from"],
            envelope["body"],
            message_id=envelope["id"],
            ts=envelope["ts"],
        )
        if created:
            self.stats["messages_received"] += 1
        else:
            self.stats["duplicates"] += 1
        if self.role == "tracker":
            self._relay_to_others(envelope, address)

    def _relay_to_others(self, envelope, address):
        payload = self._encode_payload(envelope)
        for peer in self.chat.peers(exclude=self.username):
            target = (peer["ip"], int(peer["port"]))
            if target == tuple(address):
                continue
            self._enqueue(target, payload)
            self.stats["relayed"] += 1

    def _handle_bye(self, frame, address):
        with self._lock:
            self._channels.pop(address, None)

    def _handle_auth_error(self, frame, address):
        logger.warning("peer %s rejected our token", address)

    def channel_stats(self):
        with self._lock:
            return {
                str(address): channel.stats()
                for address, channel in self._channels.items()
            }

    def status(self):
        result = dict(self.stats)
        result.update(
            {
                "username": self.username,
                "role": self.role,
                "address": self.address,
                "tracker": self.tracker,
                "peers": len(self.chat.peers()),
                "channels": len(self._channels),
            }
        )
        return result
