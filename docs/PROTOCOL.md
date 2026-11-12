# StreapRous chat protocol (Phase 4)

This document is the protocol specification required by Assignment 1, step 1.
It describes the UDP framing, the connection states, and the chat flow the
implementation supports.

Everything below is implemented in:

| Concern | File |
| --- | --- |
| Frame codec, envelope | `daemon/protocol.py` |
| Windows, ACKs, RTO, congestion control | `daemon/udp_transport.py` |
| Presence, discovery, delivery, relay | `daemon/peer.py` |
| Channels, membership, persistence | `daemon/chat.py`, `daemon/database.py` |
| Browser-facing JSON API | `apps/chatapp.py` |
| Payload encryption (optional) | `daemon/crypto.py` |

## 1. Frame format

Every UDP datagram is one frame: a fixed 16-byte header followed by a payload.
All integers are unsigned and big-endian.

```
 0        2   3   4        8        12      14     16
+--------+---+---+--------+--------+-------+------+
| "SR"   |VER|TYP|  seq   |  ack   |window | len  |
+--------+---+---+--------+--------+-------+------+
| payload ... (len bytes, at most 1384)             |
+---------------------------------------------------+
```

| Field | Size | Meaning |
| --- | --- | --- |
| magic | 2 | ASCII `SR` |
| version | 1 | `1` |
| type | 1 | frame type from the table below |
| seq | 4 | sender's sequence number; `0` means "this frame carries no data" |
| ack | 4 | next sequence number the sender expects from the peer |
| window | 2 | free space in the sender's receive buffer, in frames |
| len | 2 | payload length; the datagram must match exactly |

Sequence numbers are per direction and per peer, start at 1, and advance by one
per data frame. Pure ACK frames use `seq = 0` so they do not consume a sequence
number and cannot trigger an ACK of an ACK.

| Type | Name | Payload |
| --- | --- | --- |
| 1 | `HELLO` | JSON `{username, ip, port, token}` |
| 2 | `HELLO_ACK` | JSON `{peers: [{username, ip, port}]}` |
| 3 | `PING` | JSON `{username, token, ip, port}` |
| 4 | `PONG` | JSON `{peers: [...]}` |
| 7 | `AUTH_ERR` | JSON `{error}` |
| 8 | `MSG` | JSON `{envelope: {...}, token: "..."}` |
| 9 | `MSG_ACK` | empty (pure acknowledgement) |
| 14 | `BYE` | empty |

Unknown types, bad magic, bad version, or a length field that disagrees with the
datagram are dropped and counted as malformed; the receiver never crashes.

## 2. Message envelope

```json
{
  "v": 1,
  "id": "6f1c2f9d8b7a4c3e9f0a1b2c3d4e5f60",
  "channel": "0d5c...e1",
  "from": "alice",
  "to": "*",
  "body": "hello",
  "ts": 1730000000
}
```

* `id` is a UUID4 hex string and the dedupe key: a message delivered twice is
  stored once.
* `channel` is a UUID4 hex channel identifier; channel *names* are unique but
  replicas key on the id.
* `to` is `"*"` for broadcast or a username for a direct message.
* The peer token travels next to the envelope and must verify to `from`.

Body limit: 8 KiB UTF-8. Control characters other than `\n` and `\t` are
rejected.

## 3. Connection states

```
        HELLO / PING                    HELLO_ACK / PONG
IDLE ───────────────▶ REGISTERED ──────────────────────▶ READY
                                                   │
                          MSG                      │
                          (reliable channel)       ▼
                                              TRANSFERRING
                                                   │
                             BYE / timeout         │
                                                   ▼
                                                CLOSED
```

* `IDLE`: the node has a socket but no peer state.
* `REGISTERED`: HELLO was accepted (token verified, peer stored with
  `last_seen`). The tracker answers with the active peer list.
* `READY`: the node knows at least one peer address and can send.
* `TRANSFERRING`: at least one data frame is unacknowledged.
* `CLOSED`: `BYE`, or the retransmission budget was exhausted, or the peer was
  pruned after `peer_ttl` (20 s) without a heartbeat.

## 4. Reliability, flow control, congestion control

* Send window: `min(32 frames, cwnd, peer_window)`.
* Cumulative ACK: `ack = N` means every frame with `seq < N` was received.
* RTO starts at 400 ms and doubles per retry; after 8 retries the peer is
  declared dead and its window is dropped.
* Three duplicate ACKs trigger a fast retransmit and enter fast recovery
  (`ssthresh = cwnd/2`, `cwnd = ssthresh + 3`).
* Receive buffer holds out-of-order frames and releases them in order; frames
  below `next_expected` and duplicates are dropped and counted.
* Slow start grows `cwnd` by one frame per ACK until `ssthresh`; afterwards it
  grows by `1/cwnd`. A timeout sets `ssthresh = cwnd/2`, `cwnd = 1`.

Statistics are exposed at `GET /api/status/channels` (cwnd, ssthresh, RTT,
retransmits, duplicates, next expected).

## 5. Message flow

```
alice (peer)                    tracker                     bob (peer)
     │  HELLO(username,port,token) │                            │
     ├────────────────────────────▶│  verify token, store peer   │
     │◀─────────── HELLO_ACK(peers)│                            │
     │                             │◀──── HELLO ────────────────┤
     │                             ├──── HELLO_ACK(peers) ─────▶│
     │  PING every 5 s             │                            │
     ├────────────────────────────▶│──── PONG(peers) ──────────▶│
     │                                                          │
     │  POST /api/channels/{id}/messages                        │
     │  (browser) ──▶ store locally, then:                      │
     │  MSG(seq, ack, envelope, token) ────────────────────────▶│
     │◀────────────────────────── MSG_ACK ──────────────────────┤
```

If a peer is unreachable (window dies), the message is relayed through the
tracker, which forwards it to its registered peers. Receivers dedupe by
`envelope.id`, so relaying cannot create duplicates.

## 6. Security model

* HELLO/PING carry a peer token: `base64url(username|expiry)` plus
  HMAC-SHA256 over `b"peer:" + payload`, signed with
  `STREAPROUS_SESSION_SECRET`.
* Every MSG carries the same token, so a receiver authenticates the sender
  without keeping handshake state and without trusting the source address.
* With `STREAPROUS_CHAT_KEY` set and the `cryptography` package installed,
  MSG payloads are sealed with AES-256-GCM (`SR1 | nonce | ciphertext`).
  Without it, payloads are plaintext and the limitation is logged.

This is a course-scale design: the tracker sees metadata, tokens are bearer
credentials, and there is no forward secrecy.
