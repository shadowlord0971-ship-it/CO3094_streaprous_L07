"""Reliable UDP framing: windows, ACKs, retransmission, congestion control."""

import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace

from . import protocol

DEFAULT_CAPACITY = 32
DEFAULT_RTO = 0.4
DEFAULT_MAX_RETRIES = 8
INITIAL_CWND = 4
INITIAL_SSTHRESH = 16
TICK_SECONDS = 0.05


@dataclass(slots=True)
class Pending:
    """One unacknowledged outbound frame."""

    frame: object
    first_sent: float
    sent_at: float
    retries: int = 0


class RecvWindow:
    """In-order delivery buffer with duplicate suppression."""

    def __init__(self, capacity=DEFAULT_CAPACITY):
        self.capacity = int(capacity)
        self.next_expected = 1
        self.buffer = {}
        self.received = 0
        self.duplicates = 0
        self.out_of_order = 0

    def free(self):
        return max(0, self.capacity - len(self.buffer))

    def push(self, seq, frame):
        """Buffer ``frame`` and return the frames now deliverable in order."""
        if seq <= 0:
            return []
        if seq < self.next_expected or seq in self.buffer:
            self.duplicates += 1
            return []
        self.buffer[seq] = frame
        self.received += 1
        if seq != self.next_expected:
            self.out_of_order += 1
        delivered = []
        while self.next_expected in self.buffer:
            delivered.append(self.buffer.pop(self.next_expected))
            self.next_expected += 1
        return delivered

    def stats(self):
        return {
            "received": self.received,
            "duplicates": self.duplicates,
            "out_of_order": self.out_of_order,
            "buffered": len(self.buffer),
            "next_expected": self.next_expected,
        }


class SendWindow:
    """Sliding window with RTO, fast retransmit and AIMD congestion control."""

    def __init__(
        self,
        capacity=DEFAULT_CAPACITY,
        *,
        rto=DEFAULT_RTO,
        max_retries=DEFAULT_MAX_RETRIES,
        initial_cwnd=INITIAL_CWND,
        ssthresh=INITIAL_SSTHRESH,
    ):
        self.capacity = int(capacity)
        self.rto = float(rto)
        self.max_retries = int(max_retries)
        self.cwnd = float(initial_cwnd)
        self.ssthresh = float(ssthresh)
        self.next_seq = 1
        self.last_ack = 0
        self.dup_acks = 0
        self.unacked = OrderedDict()
        self.rtt = None
        self.dead = False
        self._counters = {
            "sent": 0,
            "acked": 0,
            "retransmits": 0,
            "fast_retransmits": 0,
            "timeouts": 0,
            "dead": 0,
        }

    def effective_window(self, peer_window):
        return max(
            1, int(min(self.capacity, max(1.0, self.cwnd), max(1, int(peer_window))))
        )

    def can_send(self, peer_window):
        return not self.dead and len(self.unacked) < self.effective_window(peer_window)

    def track(self, frame, now=None):
        """Assign the next sequence number and remember the frame."""
        now = time.monotonic() if now is None else now
        if self.dead:
            return None
        sequence = self.next_seq
        self.next_seq += 1
        pending = Pending(replace(frame, seq=sequence), now, now)
        self.unacked[sequence] = pending
        self._counters["sent"] += 1
        return pending.frame

    def acknowledge(self, ack, now=None):
        """Return ``(acked_sequences, fast_retransmit_frame)``."""
        now = time.monotonic() if now is None else now
        if ack <= 0:
            return [], None

        if ack > self.last_ack:
            self.last_ack = ack
            self.dup_acks = 0
            acked = [seq for seq in list(self.unacked) if seq < ack]
            for seq in acked:
                pending = self.unacked.pop(seq)
                sample = now - pending.first_sent
                self._update_rtt(sample)
                self._grow_window()
                self._counters["acked"] += 1
            return acked, None

        if ack == self.last_ack and self.unacked:
            self.dup_acks += 1
            if self.dup_acks == 3 and ack in self.unacked:
                pending = self.unacked[ack]
                pending.sent_at = now
                self._counters["fast_retransmits"] += 1
                # fast recovery
                self.ssthresh = max(self.cwnd / 2.0, 2.0)
                self.cwnd = self.ssthresh + 3
                return [], pending.frame
        return [], None

    def _update_rtt(self, sample):
        if sample < 0:
            return
        if self.rtt is None:
            self.rtt = sample
        else:
            self.rtt = 0.875 * self.rtt + 0.125 * sample

    def _grow_window(self):
        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0  # slow start: one MSS per ACK
        else:
            self.cwnd += 1.0 / max(self.cwnd, 1.0)  # congestion avoidance

    def due(self, now=None):
        """Return frames whose retransmission timer expired."""
        now = time.monotonic() if now is None else now
        if self.dead:
            return []
        ready = []
        for pending in list(self.unacked.values()):
            timeout = self.rto * (2 ** pending.retries)
            if now - pending.sent_at < timeout:
                continue
            if pending.retries >= self.max_retries:
                self.dead = True
                self._counters["dead"] += 1
                break
            pending.retries += 1
            pending.sent_at = now
            self._counters["retransmits"] += 1
            ready.append(pending.frame)
        if ready:
            self._counters["timeouts"] += 1
            self.ssthresh = max(self.cwnd / 2.0, 2.0)
            self.cwnd = 1.0
            self.dup_acks = 0
        return ready

    def stats(self):
        stats = dict(self._counters)
        stats.update(
            {
                "cwnd": round(self.cwnd, 3),
                "ssthresh": round(self.ssthresh, 3),
                "rtt": None if self.rtt is None else round(self.rtt, 6),
                "in_flight": len(self.unacked),
                "next_seq": self.next_seq,
                "last_ack": self.last_ack,
                "dup_acks": self.dup_acks,
                "dead": self.dead,
            }
        )
        return stats


class ReliableChannel:
    """Per-peer reliable channel: send window, receive window and state."""

    def __init__(
        self,
        address,
        *,
        capacity=DEFAULT_CAPACITY,
        rto=DEFAULT_RTO,
        max_retries=DEFAULT_MAX_RETRIES,
        clock=time.monotonic,
    ):
        self.address = address
        self.clock = clock
        self.send = SendWindow(
            capacity, rto=rto, max_retries=max_retries
        )
        self.recv = RecvWindow(capacity)
        self.peer_window = capacity
        self.last_seen = clock()

    def queue(self, frame_type, payload=b"", now=None):
        """Return a frame to transmit, or ``None`` when the window is full."""
        now = self.clock() if now is None else now
        if not self.send.can_send(self.peer_window):
            return None
        frame = protocol.Frame(
            frame_type,
            seq=0,
            ack=self.recv.next_expected,
            window=self.recv.free(),
            payload=payload,
        )
        return self.send.track(frame, now)

    def acknowledgement(self, now=None):
        """Return a pure ACK frame (seq 0 carries no data)."""
        return protocol.Frame(
            protocol.MSG_ACK,
            seq=0,
            ack=self.recv.next_expected,
            window=self.recv.free(),
        )

    def poll(self, now=None):
        """Return retransmissions that are due."""
        now = self.clock() if now is None else now
        return self.send.due(now)

    def receive(self, frame, now=None):
        """Apply an inbound frame and return frames now deliverable in order."""
        now = self.clock() if now is None else now
        self.last_seen = now
        if frame.window:
            self.peer_window = max(1, int(frame.window))
        if frame.ack:
            self.send.acknowledge(frame.ack, now)
        if frame.seq:
            return self.recv.push(frame.seq, frame)
        return []

    @property
    def dead(self):
        return self.send.dead

    def stats(self):
        return {
            "address": self.address,
            "send": self.send.stats(),
            "recv": self.recv.stats(),
            "peer_window": self.peer_window,
        }


class UdpNode:
    """A UDP endpoint that decodes protocol frames on a background thread."""

    def __init__(self, handler=None, bind_ip="0.0.0.0", bind_port=0):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((bind_ip, int(bind_port)))
        self._socket.settimeout(TICK_SECONDS)
        self.host, self.port = self._socket.getsockname()[:2]
        self.handler = handler
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self.stats = {"received": 0, "malformed": 0, "sent": 0, "errors": 0}

    @property
    def address(self):
        return (self.host, self.port)

    def start(self):
        if self._thread is not None:
            return self
        self._thread = threading.Thread(
            target=self._loop, name=f"udp-node-{self.port}", daemon=True
        )
        self._thread.start()
        return self

    def stop(self, timeout=2.0):
        self._stop.set()
        try:
            self._socket.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, address = self._socket.recvfrom(protocol.MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self.stats["received"] += 1
            try:
                frame = protocol.decode_frame(data)
            except protocol.ProtocolError:
                with self._lock:
                    self.stats["malformed"] += 1
                continue
            if self.handler is None:
                continue
            try:
                self.handler(frame, address)
            except Exception:
                with self._lock:
                    self.stats["errors"] += 1

    def send(self, frame, address):
        if isinstance(frame, protocol.Frame):
            data = frame.encode()
        else:
            data = bytes(frame)
        self._socket.sendto(data, (address[0], int(address[1])))
        with self._lock:
            self.stats["sent"] += 1


__all__ = [
    "DEFAULT_CAPACITY",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_RTO",
    "Pending",
    "RecvWindow",
    "ReliableChannel",
    "SendWindow",
    "UdpNode",
]
