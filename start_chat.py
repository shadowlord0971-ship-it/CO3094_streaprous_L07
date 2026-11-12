"""Run the chat daemon (HTTP UI + UDP peer transport)."""

import argparse
import os
import sys

from apps.chatapp import create_chatapp


def parse_endpoint(value):
    """Parse ``host:port`` into a ``(host, port)`` tuple."""
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("expected host:port, e.g. 127.0.0.1:9100")
    try:
        port = int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return host, port


def build_parser():
    parser = argparse.ArgumentParser(
        prog="start_chat", description="StreapRous chat daemon"
    )
    parser.add_argument("--mode", choices=("peer", "tracker", "local"), default="peer")
    parser.add_argument("--server-ip", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=8000)
    parser.add_argument("--udp-port", type=int, default=9100)
    parser.add_argument(
        "--tracker",
        type=parse_endpoint,
        default=None,
        help="tracker UDP address as host:port (peer mode)",
    )
    parser.add_argument("--public-ip", default=None)
    parser.add_argument("--username", default=None, help="this node's account")
    parser.add_argument("--db", default=os.path.join("data", "chat.sqlite3"))
    parser.add_argument(
        "--transport",
        choices=("standard", "async", "auto"),
        default="standard",
        help="HTTP transport; 'standard' works without root",
    )
    parser.add_argument(
        "--heartbeat", type=float, default=5.0, help="tracker heartbeat seconds"
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.mode == "peer" and not args.username:
        print("error: --username is required in peer mode", file=sys.stderr)
        return 2
    if args.mode == "peer" and args.tracker is None:
        print("error: --tracker is required in peer mode", file=sys.stderr)
        return 2

    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    create_chatapp(
        args.server_ip,
        args.server_port,
        mode=args.mode,
        tracker=args.tracker,
        db_path=args.db,
        udp_port=args.udp_port,
        public_ip=args.public_ip,
        username=args.username,
        transport=args.transport,
        heartbeat=args.heartbeat,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
