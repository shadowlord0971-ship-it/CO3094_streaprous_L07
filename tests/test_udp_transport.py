"""Tests for the UDP transport."""

import threading
import unittest

from daemon import protocol
from daemon.udp_transport import (
    RecvWindow,
    ReliableChannel,
    SendWindow,
    UdpNode,
)


class FakeClock:
    def __init__(self, start=0.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RecvWindowTests(unittest.TestCase):
    def setUp(self):
        self.window = RecvWindow(capacity=4)

    def test_in_order_delivery(self):
        delivered = self.window.push(1, "one")
        self.assertEqual(delivered, ["one"])
        self.assertEqual(self.window.next_expected, 2)

    def test_out_of_order_frames_are_buffered_and_released_in_order(self):
        self.assertEqual(self.window.push(3, "three"), [])
        self.assertEqual(self.window.push(2, "two"), [])
        self.assertEqual(self.window.out_of_order, 2)
        self.assertEqual(self.window.free(), 2)
        delivered = self.window.push(1, "one")
        self.assertEqual(delivered, ["one", "two", "three"])
        self.assertEqual(self.window.next_expected, 4)
        self.assertEqual(self.window.free(), 4)

    def test_duplicates_are_dropped(self):
        self.window.push(1, "one")
        self.assertEqual(self.window.push(1, "one"), [])
        self.assertEqual(self.window.duplicates, 1)

    def test_sequence_zero_is_not_data(self):
        self.assertEqual(self.window.push(0, "ack"), [])
        self.assertEqual(self.window.next_expected, 1)

    def test_free_space_shrinks_with_buffered_frames(self):
        self.window.push(2, "two")
        self.assertEqual(self.window.free(), 3)


class SendWindowTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock(100.0)
        self.window = SendWindow(capacity=8, rto=1.0, initial_cwnd=4)

    def _track(self, count=1):
        frames = []
        for index in range(count):
            frame = protocol.Frame(protocol.MSG, payload=str(index).encode())
            frames.append(self.window.track(frame, self.clock.now))
        return frames

    def test_sequence_numbers_start_at_one(self):
        frames = self._track(2)
        self.assertEqual([frame.seq for frame in frames], [1, 2])
        self.assertEqual(len(self.window.unacked), 2)

    def test_congestion_window_limits_in_flight_frames(self):
        self._track(4)
        self.assertFalse(self.window.can_send(peer_window=8))
        self.assertTrue(self.window.can_send(peer_window=8) is False)
        self.window.acknowledge(2, self.clock.now)
        self.assertTrue(self.window.can_send(peer_window=8))

    def test_peer_window_can_be_smaller_than_cwnd(self):
        self.assertEqual(self.window.effective_window(peer_window=2), 2)
        self._track(2)
        self.assertFalse(self.window.can_send(peer_window=2))

    def test_cumulative_ack_releases_frames_and_grows_window(self):
        self._track(3)
        acked, fast = self.window.acknowledge(3, self.clock.now + 0.1)
        self.assertEqual(acked, [1, 2])
        self.assertIsNone(fast)
        self.assertEqual(len(self.window.unacked), 1)
        self.assertGreater(self.window.cwnd, 4)
        self.assertAlmostEqual(self.window.rtt, 0.1, places=6)

    def test_three_duplicate_acks_trigger_fast_retransmit(self):
        self._track(4)
        acked, fast = self.window.acknowledge(2, self.clock.now)
        self.assertEqual(acked, [1])
        self.assertIsNone(fast)
        for offset in (0.01, 0.02):
            _acked, fast = self.window.acknowledge(2, self.clock.now + offset)
            self.assertIsNone(fast)
        _acked, fast = self.window.acknowledge(2, self.clock.now + 0.03)
        self.assertIsNotNone(fast)
        self.assertEqual(fast.seq, 2)
        self.assertEqual(self.window.stats()["fast_retransmits"], 1)
        self.assertLess(self.window.cwnd, self.window.ssthresh + 4)

    def test_timeout_retransmits_and_resets_congestion_window(self):
        self._track(2)
        self.assertEqual(self.window.due(self.clock.now + 0.5), [])
        retransmit = self.window.due(self.clock.now + 1.0)
        self.assertEqual([frame.seq for frame in retransmit], [1, 2])
        self.assertEqual(self.window.cwnd, 1.0)
        self.assertEqual(self.window.stats()["timeouts"], 1)

    def test_backoff_doubles_the_next_timeout(self):
        self._track(1)
        self.clock.advance(1.0)
        self.assertEqual(len(self.window.due(self.clock.now)), 1)
        self.assertEqual(self.window.due(self.clock.now + 1.5), [])
        self.assertEqual(len(self.window.due(self.clock.now + 2.0)), 1)

    def test_window_dies_after_max_retries(self):
        window = SendWindow(capacity=4, rto=0.1, max_retries=1, initial_cwnd=2)
        window.track(protocol.Frame(protocol.MSG, payload=b"x"), 0.0)
        self.assertEqual(len(window.due(0.2)), 1)
        window.due(0.2 + 0.2 * 2)
        self.assertTrue(window.dead)
        self.assertEqual(window.stats()["dead"], 1)


class ReliableChannelTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.channel = ReliableChannel(
            ("127.0.0.1", 9000), capacity=8, rto=1.0, clock=self.clock
        )

    def test_queue_assigns_sequence_and_advertises_window(self):
        frame = self.channel.queue(protocol.MSG, b"payload", self.clock.now)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.seq, 1)
        self.assertEqual(frame.ack, 1)
        self.assertEqual(frame.window, 8)

    def test_queue_stops_when_window_is_full(self):
        sent = 0
        while self.channel.queue(protocol.MSG, b"x", self.clock.now) is not None:
            sent += 1
            self.assertLess(sent, 100)
        # The initial congestion window (4) is smaller than the capacity (8).
        self.assertEqual(sent, 4)

    def test_acknowledgement_reports_next_expected(self):
        self.channel.queue(protocol.MSG, b"x", self.clock.now)
        ack = self.channel.acknowledgement(self.clock.now)
        self.assertEqual(ack.seq, 0)
        self.assertEqual(ack.ack, 1)

    def test_receive_releases_in_order(self):
        first = protocol.Frame(protocol.MSG, 1, 0, 8, b"one")
        second = protocol.Frame(protocol.MSG, 2, 0, 8, b"two")
        self.assertEqual(self.channel.receive(second), [])
        self.assertEqual(self.channel.receive(first), [first, second])

    def test_receive_applies_ack(self):
        self.channel.queue(protocol.MSG, b"x", self.clock.now)
        self.channel.receive(protocol.Frame(protocol.MSG_ACK, 0, 2, 8))
        self.assertEqual(len(self.channel.send.unacked), 0)

    def test_stats_are_json_safe(self):
        self.channel.queue(protocol.MSG, b"x", self.clock.now)
        stats = self.channel.stats()
        self.assertEqual(stats["address"], ("127.0.0.1", 9000))
        self.assertIn("cwnd", stats["send"])
        self.assertIn("received", stats["recv"])


class TransferSimulationTests(unittest.TestCase):
    def _transfer(self, total, *, drop=None):
        clock = FakeClock()
        sender = ReliableChannel(("b", 1), capacity=8, rto=1.0, clock=clock)
        receiver = ReliableChannel(("a", 1), capacity=8, rto=1.0, clock=clock)
        payloads = [f"m{index}".encode() for index in range(total)]
        delivered = []
        next_payload = 0
        dropped = False
        attempts = 0

        while len(delivered) < total and attempts < 4000:
            attempts += 1
            clock.advance(0.05)
            while len(delivered) < total:
                frame = sender.queue(protocol.MSG, payloads[next_payload], clock.now)
                if frame is None:
                    break
                next_payload += 1
                if drop is not None and frame.seq == drop and not dropped:
                    dropped = True
                    continue
                delivered.extend(receiver.receive(frame, clock.now))
                sender.receive(receiver.acknowledgement(clock.now), clock.now)

            for frame in sender.poll(clock.now):
                delivered.extend(receiver.receive(frame, clock.now))
                sender.receive(receiver.acknowledgement(clock.now), clock.now)

        return delivered, sender, receiver, dropped

    def test_order_is_preserved_without_loss(self):
        delivered, sender, _receiver, _ = self._transfer(50)
        self.assertEqual([frame.payload for frame in delivered],
                         [f"m{index}".encode() for index in range(50)])
        self.assertEqual(sender.send.stats()["retransmits"], 0)

    def test_a_dropped_frame_is_recovered(self):
        delivered, sender, _receiver, dropped = self._transfer(20, drop=3)
        self.assertTrue(dropped)
        self.assertEqual(len(delivered), 20)
        self.assertEqual(
            [frame.payload for frame in delivered],
            [f"m{index}".encode() for index in range(20)],
        )
        stats = sender.send.stats()
        self.assertGreaterEqual(
            stats["retransmits"] + stats["fast_retransmits"], 1
        )


class UdpNodeTests(unittest.TestCase):
    def test_loopback_delivery(self):
        received = []
        event = threading.Event()

        def handler(frame, address):
            received.append((frame, address))
            event.set()

        server = UdpNode(handler, "127.0.0.1", 0).start()
        client = UdpNode(None, "127.0.0.1", 0).start()
        self.addCleanup(server.stop)
        self.addCleanup(client.stop)

        client.send(protocol.hello("alice", "127.0.0.1", 9101, "t"), server.address)
        self.assertTrue(event.wait(3.0), "server did not receive the datagram")
        frame, address = received[0]
        self.assertEqual(frame.type, protocol.HELLO)
        self.assertEqual(frame.json_payload()["username"], "alice")
        self.assertEqual(address[0], "127.0.0.1")

    def test_malformed_datagrams_are_counted_not_fatal(self):
        server = UdpNode(lambda frame, addr: None, "127.0.0.1", 0).start()
        client = UdpNode(None, "127.0.0.1", 0).start()
        self.addCleanup(server.stop)
        self.addCleanup(client.stop)

        client.send(b"not-a-frame", server.address)
        client.send(protocol.ping("bob", "t"), server.address)
        for _ in range(100):
            if server.stats["malformed"]:
                break
            threading.Event().wait(0.02)
        self.assertEqual(server.stats["malformed"], 1)
        self.assertGreaterEqual(server.stats["received"], 1)

    def test_stop_is_idempotent(self):
        node = UdpNode(None, "127.0.0.1", 0).start()
        node.stop()
        node.stop()


if __name__ == "__main__":
    unittest.main()
