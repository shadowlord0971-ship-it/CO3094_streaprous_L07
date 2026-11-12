"""Chat app: JSON control plane plus the UDP peer node."""

import functools
import logging
import os

from daemon.auth import install_auth
from daemon.chat import ChatService
from daemon.errors import BadRequest, HTTPError
from daemon.peer import PeerNode
from daemon.response import Response
from daemon.streaprous import StreapRous

DEFAULT_DB = os.path.join("data", "chat.sqlite3")
logger = logging.getLogger(__name__)


def _payload_cipher():
    """Build an AES-GCM cipher when STREAPROUS_CHAT_KEY is configured."""
    secret = os.environ.get("STREAPROUS_CHAT_KEY")
    if not secret:
        return None
    from daemon import crypto

    if not crypto.available():
        logger.warning(
            "STREAPROUS_CHAT_KEY is set but 'cryptography' is missing; "
            "peer payloads will be sent in plaintext"
        )
        return None
    return crypto.PayloadCipher.from_secret(secret)



def _api(view):
    """Convert domain errors into JSON responses instead of tracebacks."""

    @functools.wraps(view)
    def wrapper(request):
        try:
            return view(request)
        except HTTPError as exc:
            return Response().json({"error": exc.message}, status=exc.status_code)
        except ValueError as exc:
            return Response().json({"error": str(exc)}, status=400)

    return wrapper


def _json_object(request):
    if not request.body:
        return {}
    data = request.json
    if not isinstance(data, dict):
        raise BadRequest("request body must be a JSON object")
    return data


def _since(request):
    raw = (request.query.get("since") or ["0"])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise BadRequest("since must be an integer") from exc
    if value < 0:
        raise BadRequest("since must not be negative")
    return value


def _limit(request):
    raw = (request.query.get("limit") or ["100"])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise BadRequest("limit must be an integer") from exc
    return max(1, min(value, 500))


def build_chatapp(
    *,
    mode="peer",
    tracker=None,
    db_path=None,
    udp_port=0,
    public_ip=None,
    username=None,
    heartbeat=5.0,
    install_peer=True,
    password_iterations=None,
):
    """Create the app, wire services and register every chat route."""
    mode = (mode or "peer").lower()
    if mode not in ("peer", "tracker", "local"):
        raise ValueError("mode must be 'peer', 'tracker' or 'local'")

    app = StreapRous()
    auth = install_auth(
        app,
        db_path or DEFAULT_DB,
        password_iterations=password_iterations,
    )
    chat = ChatService(auth.database)
    app._streaprous_chat = chat
    app._streaprous_auth = auth

    peer = None
    if install_peer and mode != "local":
        node_user = username or ("tracker" if mode == "tracker" else None)
        if not node_user:
            raise ValueError("username is required for peer mode")
        cipher = _payload_cipher()
        peer = PeerNode(
            chat,
            username=node_user,
            token=auth.issue_peer_token(node_user, ttl=24 * 3600),
            verifier=auth.verify_peer_token,
            role="tracker" if mode == "tracker" else "peer",
            udp_port=udp_port,
            public_ip=public_ip,
            tracker=tracker,
            heartbeat=heartbeat,
            cipher=cipher,
        )
        peer.start()
    app._streaprous_peer = peer
    app._streaprous_mode = mode

    @app.route("/api/status", methods=["GET"])
    def status(request):
        return {
            "mode": mode,
            "node": peer.status() if peer is not None else None,
            "channels": len(chat.list_channels(user_id=0)),
        }

    @app.route("/api/status/channels", methods=["GET"], auth=True)
    @_api
    def channel_stats(request):
        if peer is None:
            return {"channels": {}}
        return {"channels": peer.channel_stats()}

    @app.route("/api/channels", methods=["GET"], auth=True)
    @_api
    def list_channels(request):
        return {"channels": chat.list_channels(request.user["id"])}

    @app.route("/api/channels", methods=["POST"], auth=True)
    @_api
    def create_channel(request):
        data = _json_object(request)
        try:
            channel = chat.create_channel(
                data.get("name", ""),
                request.user,
                is_private=bool(data.get("private", False)),
            )
        except BadRequest:
            raise
        except ValueError:
            return Response().json(
                {"error": "channel already exists"}, status=409
            )
        return Response().json({"channel": channel}, status=201)

    @app.route("/api/channels/{channel_id}/join", methods=["POST"], auth=True)
    @_api
    def join_channel(request):
        channel = chat.require_channel(request.path_params["channel_id"])
        chat.join(channel["id"], request.user)
        return Response().no_content()

    @app.route("/api/channels/{channel_id}/leave", methods=["POST"], auth=True)
    @_api
    def leave_channel(request):
        channel = chat.require_channel(request.path_params["channel_id"])
        chat.leave(channel["id"], request.user)
        return Response().no_content()

    @app.route(
        "/api/channels/{channel_id}/messages", methods=["GET"], auth=True
    )
    @_api
    def list_messages(request):
        channel_id = request.path_params["channel_id"]
        chat.require_member(channel_id, request.user)
        rows = chat.messages(channel_id, since=_since(request), limit=_limit(request))
        next_since = rows[-1]["seq"] if rows else _since(request)
        return {"messages": rows, "next_since": next_since}

    @app.route(
        "/api/channels/{channel_id}/messages", methods=["POST"], auth=True
    )
    @_api
    def post_message(request):
        channel_id = request.path_params["channel_id"]
        chat.require_member(channel_id, request.user)
        data = _json_object(request)
        body = data.get("body", "")
        client_id = data.get("client_id")
        recipient = data.get("to") or "*"
        sender = request.user["username"]

        if peer is not None:
            try:
                if recipient == "*":
                    message = peer.broadcast(
                        channel_id, body, message_id=client_id, sender=sender
                    )
                else:
                    message = peer.send_direct(
                        channel_id,
                        recipient,
                        body,
                        message_id=client_id,
                        sender=sender,
                    )
            except PermissionError:
                message, _created = chat.post_message(
                    channel_id, sender, body, message_id=client_id
                )
        else:
            message, _created = chat.post_message(
                channel_id, sender, body, message_id=client_id
            )
        return Response().json({"message": message}, status=201)

    @app.route("/api/peers", methods=["GET"], auth=True)
    @_api
    def list_peers(request):
        return {"peers": chat.peers(exclude=peer.username if peer else None)}

    @app.route("/api/peers/heartbeat", methods=["POST"], auth=True)
    @_api
    def peer_heartbeat(request):
        data = _json_object(request)
        chat.register_peer(
            request.user["username"],
            data.get("ip") or (request.remote_addr[0] if request.remote_addr else "127.0.0.1"),
            data.get("port") or 0,
        )
        return Response().no_content()

    return app


def create_chatapp(ip, port, **kwargs):
    """Build the app, bind the address and start serving."""
    transport = kwargs.pop("transport", None)
    app = build_chatapp(**kwargs)
    app.prepare_address(ip, port)
    app.run(transport=transport)
    return app
