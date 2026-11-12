#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
StreapRous Raw Connection Library
A library for handling TCP connections with raw sockets.
Based on raw_connection_server.py implementation.
Provides connection management, send/receive functionality using raw sockets.
"""

import queue
import socket
import struct
import sys
import threading
import time
from collections import namedtuple

try:  # Optional: only the raw transport uses interface detection.
    import netifaces
except ImportError:  # pragma: no cover - depends on host packages
    netifaces = None

# Import streaprout packet dispatcher functions
from .streaprous_packet_dispatcher import (
    _SYN_KEY,
    _packet_dispatcher_lock,
    get_packet_queue,
    remove_packet_queue,
    start_packet_dispatcher,
    stop_packet_dispatcher,
)

# Connection structure 
# This structure holds connection and its state information
conn_struct = namedtuple('conn_struct', [
    'client_ip',
    'client_port',
    'server_ip',
    'server_port',
    'state',
    'server_seq',
    'client_seq',
    'expected_final_ack',
    'last_activity'
])


# Global table to manage multiple connection
# The mapping include {key: value} as { (client_ip, client_port): conn_struct }
connections = {}
connections_lock = threading.Lock()

# Management structure to serialize the 3-way handshake
# Each hand shake is manage by a unique ID client_key
# including client_ip client_port
handshake_lock = threading.Lock()
handshake_in_progress = {}


# Default raw port listener
DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_LISTEN_PORT = 22239
DEFAULT_INTERFACE_NAME = "lo0"

def register_keep_port_alive(listen_ip="0.0.0.0", listen_port=22239, retry_interval=10):
    """
    Periodically register and maintain TCP port.
    Retry registration whenever binding/listening fails.
    Never accept incoming connections.
    
    Args:
        listen_ip: IP address to bind to (default: "0.0.0.0")
        listen_port: Port to bind to (default: 22239)
        retry_interval: Seconds to wait before retrying after failure (default: 10)
    
    Returns:
        threading.Thread: The background thread running the port keep-alive
    """
    def _keep_alive():
        print(f"[Streap_raw]  Start port keep-alive thread for {listen_ip}:{listen_port}")
        attempt = 0
        while True:
            attempt += 1
            standard_sock = None

            try:
                print(f"[Streap_raw] register_keep_port_alive: Attempt #{attempt} - Create socket...")
                standard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                standard_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                print(f"[Streap_raw] register_keep_port_alive: Bind to {listen_ip}:{listen_port}...")
                standard_sock.bind((listen_ip, listen_port))
                
                print(f"[Streap_raw] register_keep_port_alive: Listen on port {listen_port}...")
                standard_sock.listen(0)  # No backlog, we won't accept connections
                print(f"[Streap_raw] register_keep_port_alive: Done port {listen_port} registration.")

                # Keep socket alive until an error occurs.
                while True:
                    time.sleep(3600)
            except Exception as e:
                print(f"[Streap_raw] register_keep_port_alive: Fail port registration with error {e}")
            finally:
                if standard_sock:
                    print(f"[Streap_raw] register_keep_port_alive: Close socket...")
                    standard_sock.close()

            print(f"[Streap_raw] register_keep_port_alive: Retry port registration in {retry_interval}s... (attempt #{attempt + 1})")
            time.sleep(retry_interval)
    
    print(f"[Streap_raw] register_keep_port_alive: Starting background thread for port {listen_port}")
    thread = threading.Thread(target=_keep_alive, daemon=True, name=f"port-keep-alive-{listen_port}")
    thread.start()
    print(f"[Streap_raw] register_keep_port_alive: Thread started (name={thread.name})")
    return thread


def checksum(msg):
    """Calculates a checksum and returns computed values.

    Args:
         msg message data
    """
    if len(msg) % 2 == 1:
        msg += b'\x00'
    s = 0
    for i in range(0, len(msg), 2):
        w = struct.unpack('!H', msg[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def build_tcp_packet(src_ip, dest_ip, src_port, dst_port, seq, ack_seq, syn=0, ack=0, fin=0):
    """Stitches a structurally flawless 20-byte TCP header.

    Args:
         src_ip    Source IP address
         dest_ip   Destination IP address
         src_port  Source port
         dst_port  Destination port
         seq       Sequence number
         ack_seq   ACK for sequence
         syn=0     SYN flag
         ack=0     ACK flag
         fin=0     FIN flag
    """
    flags = (ack << 4) + (syn << 1) + fin
    offset_res = (5 << 4) + 0  # 20 bytes data offset (5 * 4)
    window = 5840
    urg_ptr = 0
    draft_checksum = 0

    # Build a draft (20 byte) header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    
    # Build addressing-header
    address_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, len(tcp_header_temp)
    )
    
    # Calculate mathematical checksum integer
    tcp_checksum = checksum(address_header+ tcp_header_temp)
    
    # Build the final TCP packet
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )
    
    return tcp_header


def build_ip_header(src_ip, dest_ip, protocol, payload_len):
    """Builds a structurally flawless 20-byte IP header.

    Args:
         src_ip       Source IP address
         dest_ip      Destination IP address
         protocol     Protocol number
         payload_len  Payload length
    """
    version_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + payload_len  # IP header + payload

    # TODO: We draft with no-fragment package
    #       Full implementation must include fragment
    #       handling function
    identification = 0x1234
    flags_fragment = 0x4000
    flags_offset = 0 
    ttl = 64
    draft_checksum = 0
    
    # Build draft header with no checksum
    ip_header_temp = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, draft_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )
    
    # Calculate the checksum
    ip_checksum = checksum(ip_header_temp)
    
    # Build the final IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, ip_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )
    
    return ip_header


def send_tcp_data_segment(s, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, payload):
    """Assembles and transmits a single TCP segment containing data payload.

    Args:
         src_ip       Source IP address
         dest_ip      Destination IP address
         src_port     Source port
         dst_port     Destination port
         seq          Sequence number
         ack_seq      ACK for sequence
         syn          SYN flag
         ack          ACK flag
         payload      Payload

    """

    # TODO: Hardcode for fast data pushing
    #       The setting PSH + ACK
    #       need to modify in full schema
    flags = 0x18
    offset_res = (5 << 4) + 0
    window = 5840
    urg_ptr = 0
    draft_checksum = 0
    
    # Build draft header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    
    tcp_len = len(tcp_header_temp) + len(payload)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, tcp_len
    )

    # Calculate the checksum    
    tcp_checksum = checksum(pseudo + tcp_header_temp + payload)

    # Build the full TCP packet header    
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )

    # Build the full IP packet header     
    ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload))

    # Build the full packet header     
    full_packet = ip_header + tcp_header + payload

    # Send packet
    print(f"[Streap_raw] send_tcp_data_segment: seq={seq}, ack_seq={ack_seq}, payload_len={len(payload)}, flags=0x{flags:02x}")
    print(f"[Streap_raw] send_tcp_data_segment: TCP header seq={seq}, ack_seq={ack_seq}, flags=0x{flags:02x}")
    s.sendto(full_packet, (dest_ip, 0))
    
    return len(payload)


def clean_expired_connections(timeout=60):
    """Background thread to clean up stale or timed-out connections.

    Args:
         timeout Time expiration for clean-up working
    """
    while True:
        time.sleep(10)
        now = time.time()
        with connections_lock:
            expired = [k for k, session in connections.items() if now - session.last_activity > timeout]
            for k in expired:
                print(f"[Streap_raw] clean_expired_connections: Session [{k[0]}:{k[1]}] Connection timed out ({timeout}s inactivity). Remove connection.")
                del connections[k]


def create_raw_socket() -> socket.socket:
    """
    Create a raw socket for TCP protocol. The raw socket requires root privileges.
    It is raw with listen all packet for incoming port.
    
    Returns:
        Raw socket object
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # TODO: port listener need to be post-procesed later
        #       raw_socket ignore the transport protocol deatails

        print(f"[Streap_raw] Create raw socket binding for 0.0.0.0 listening")
        return sock
    except PermissionError:
        print("Error: Root privileges required (sudo).")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating raw socket: {e}")
        sys.exit(1)


def get_interface_ip(interface_name: str | None = None) -> str:
    """
    Get the IPv4 address of a network interface.
    
    Args:
        interface_name: Network interface name (e.g., 'enp0s8', 'eth0', 'en0')
                        If None, tries to find the default route interface.
    
    Returns:
        IPv4 address string
    """
    try:
        if interface_name and netifaces is not None:
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        elif netifaces is not None:
            # Try to get default route interface
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                iface = default_gateway[1]
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        pass
    
    # Fallback: try to get any non-loopback IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def accept(s: socket.socket, listen_ip: str, listen_port: int, interface_name: str | None = None) -> conn_struct:
    """
    Accept a new connection by performing the 3-way handshake using raw sockets.
    Returns a conn_struct tuple for the established connection.
    Handshakes are serialized to ensure only one 3-way handshake is processed at a time.
    
    Args:
        s: Raw socket
        listen_ip: Server IP to listen on (e.g., '0.0.0.0')
        listen_port: Server port to listen on
        interface_name: Network interface name for sending packets (optional)
    
    Returns:
        conn_struct: Established connection information
    """
    # Start packet dispatcher for this port
    start_packet_dispatcher(s, listen_port)
    
    # Get actual source IP for sending packets
    if listen_ip == "0.0.0.0":
        send_ip = get_interface_ip(interface_name)
        print(f"[Streap_raw] accept: listen_ip=0.0.0.0, using send_ip={send_ip} for outgoing packets")
    else:
        send_ip = listen_ip
    
    server_seq = 2000
    client_ip = None
    client_port = None

    print(f"[Streap_raw] accept: Waiting for incoming connections on {listen_ip}:{listen_port} (send_ip={send_ip})...")
    try:
        while True:
            # Get packet from dispatcher queue (for SYN packets)
            syn_q = get_packet_queue(_SYN_KEY)
            try:
                packet, _addr = syn_q.get(timeout=1.0)
                print(f"[Streap_raw] accept: Got packet from SYN queue")
            except queue.Empty:
                continue

            # Extract IP Header Length
            ihl = (packet[0] & 0x0F) * 4
            tcp_packet = packet[ihl:]
            
            if len(tcp_packet) < 20:
                continue

            # Unpack the received TCP header
            tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
            src_port, dest_port, pkt_seq, pkt_ack, flags = (
                tcph[0],
                tcph[1],
                tcph[2],
                tcph[3],
                tcph[5],
            )

            # Bypass non-listen port
            if dest_port != listen_port:
                continue

            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4

            # Build client_key from client IP and client port
            client_ip = socket.inet_ntoa(packet[12:16])
            client_port = src_port
            client_key = (client_ip, client_port)
            print(f"\n[Streap_raw] accept: Receiv packet from Client ({client_ip}:{client_port}) (Seq={pkt_seq}, SYN={syn_flag}, ACK={ack_flag})")

            # Create queue for each connection associated 
            # with tupple client_key=(client_ip, client_port)
            q = get_packet_queue(client_key)
            print(f"[Streap_raw] accept: Createet per-connection queue for {client_key}")
            with connections_lock:
                # Declare initialized session if not available
                if client_key not in connections:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="LISTEN",
                        server_seq=2000,
                        client_seq=0,
                        expected_final_ack=0,
                        last_activity=time.time()
                    )
                session = connections[client_key]

                        
            # Perform 3 handshake step
            # STEP 1: Obtain client SYN 
            if syn_flag == 1 and ack_flag == 0:
                print(f"\nHandshake1: Received SYN from Client ({client_ip}:{client_port}) (Seq={pkt_seq})")

                # Quick duplicate handshake check (fast, no heavy operations)
                with handshake_lock:
                    if handshake_in_progress.get(client_key, False):
                        print(f"[Streap_raw] accept: Handshake already in progress for {client_ip}:{client_port}, dropping SYN")
                        continue
                    handshake_in_progress[client_key] = True

                # STEP 2: Reply SYN-ACK immediately
                # Build TCP packet for SYN-ACK
                next_ack = pkt_seq + 1
                syn_ack_packet = build_tcp_packet(send_ip, client_ip, listen_port, client_port,
                                                  seq=server_seq, ack_seq=next_ack, syn=1, ack=1)
                ip_header = build_ip_header(send_ip, client_ip, socket.IPPROTO_TCP, len(syn_ack_packet))
                full_packet = ip_header + syn_ack_packet

                # Send SYN-ACK packet
                print(f"[Streap_raw] accept: Sending SYN-ACK to {client_ip}:{client_port} from {send_ip}:{listen_port}")
                print(f"[Streap_raw] accept: SYN-ACK packet size: {len(full_packet)} bytes (IP={len(ip_header)}, TCP={len(syn_ack_packet)})")
                bytes_sent = s.sendto(full_packet, (client_ip, 0))
                print(f"Handshake2: Sent SYN-ACK to Client (Seq={server_seq}, Ack={next_ack}, bytes_sent={bytes_sent})")

                # Register connection to the associated queue for each connection associated 
                # with tupple client_key=(client_ip, client_port)
                with connections_lock:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,  # Use actual sending IP
                        server_port=listen_port,
                        state="SYN_RCVD",
                        server_seq=server_seq,
                        client_seq=pkt_seq,
                        expected_final_ack=server_seq + 1,
                        last_activity=time.time()
                    )
                    session = connections[client_key]

                # STEP 3: Wait for client FIN-ACK
                # The final ACK will arrive on the per-connection queue, not the SYN queue
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    try:
                        packet, _addr = q.get(timeout=0.5)
                        print(f"[Streap_raw] accept: Got packet from per-connection queue for {client_ip}:{client_port}")
                    except queue.Empty:
                        print(f"[Streap_raw] accept: Per-connection queue empty for {client_ip}:{client_port}, waiting...")
                        continue

                    # Extract IP Header Length
                    ihl = (packet[0] & 0x0F) * 4
                    tcp_packet = packet[ihl:]
                    
                    if len(tcp_packet) < 20:
                        continue

                    # Unpack the received TCP header
                    tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
                    src_port, dest_port, pkt_seq, pkt_ack, flags = (
                        tcph[0],
                        tcph[1],
                        tcph[2],
                        tcph[3],
                        tcph[5],
                    )

                    syn_flag = (flags & 0x02) >> 1
                    ack_flag = (flags & 0x10) >> 4
                    print(f"[Streap_raw] accept: Received packet in handshake wait - SYN={syn_flag}, ACK={ack_flag}, Seq={pkt_seq}, Ack={pkt_ack}")

                    # Check if this is the final ACK (ACK only, no SYN)
                    if syn_flag == 0 and ack_flag == 1:
                        print(f"[Streap_raw] accept: handshake3 Received FIN-ACK from Client (Seq={pkt_seq}, Ack={pkt_ack})")

                        with connections_lock:
                            if session.state != "SYN_RCVD":
                                print(f"[Streap_raw] accept: Non handshake state for {client_ip}:{client_port}")
                                break

                            # Update connection to ESTABLISHED
                            connections[client_key] = conn_struct(
                                client_ip=client_ip,
                                client_port=client_port,
                                server_ip=send_ip,
                                server_port=listen_port,
                                state="ESTABLISHED",
                                server_seq=pkt_ack,
                                client_seq=pkt_seq,
                                expected_final_ack=session.expected_final_ack,
                                last_activity=time.time()
                            )
                            session = connections[client_key]

                        # Clear handshake in progress flag
                        with handshake_lock:
                            handshake_in_progress[client_key] = False

                        print(f"[Streap_raw] Etablished handshak with connection: ({client_ip}:{client_port}) ESTABLISHED")
                        
                        # Return the established connection info
                        return session
                
                # Fallback of the handshake timeout
                print(f"[Streap_raw] Handshake timeout for {client_ip}:{client_port}")
                with handshake_lock:
                    handshake_in_progress[client_key] = False
                remove_packet_queue(client_key)
                with connections_lock:
                    connections.pop(client_key, None)
                continue

            # STEP 3 Exception handling: Capture FIN ACK on SYN queue ---
            if session.state == "SYN_RCVD" and syn_flag == 0 and ack_flag == 1:
                print(f"[Streap_raw] accept: handshake3 received Final ACK from Client on SYN queue (Seq={pkt_seq}, Ack={pkt_ack})")
                print(f"[Streap_raw] accept: Fallback - got final ACK on SYN queue for {client_ip}:{client_port}")

                with connections_lock:
                    if session.state != "SYN_RCVD":
                        print(f"[Streap_raw] accept: Non handshake state for {client_ip}:{client_port}")
                        continue

                    # Update connection to ESTABLISHED
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="ESTABLISHED",
                        server_seq=pkt_ack,
                        client_seq=pkt_seq,
                        expected_final_ack=session.expected_final_ack,
                        last_activity=time.time()
                    )
                    session = connections[client_key]

                # Clear handshake in progress flag
                with handshake_lock:
                    handshake_in_progress[client_key] = False

                print(f"[Streap_raw] Etablished handshak with connection: ({client_ip}:{client_port}) ESTABLISHED")
                
                # Return the established connection info
                return session

    except KeyboardInterrupt:
        print("\n[-] Server stopped.")
        # Clear handshake flags on interrupt
        with handshake_lock:
            handshake_in_progress.clear()
        raise


def run_conn_recv(s: socket.socket, conn_info: conn_struct) -> bytes:
    """
    Receive data on an established connection using raw sockets.
    This function handles incoming packets for a specific connection by reading
    from the packet dispatcher's per-connection queue.
    
    Args:
        s: raw socket
        conn_info: conn_struct tuple for the connection
    
    Returns:
        bytes: The received data payload, or empty bytes if connection closed
    """
    client_ip = conn_info.client_ip
    client_port = conn_info.client_port
    client_key = (client_ip, client_port)
    listen_ip = conn_info.server_ip
    listen_port = conn_info.server_port
    
    # Get the packet queue for this connection from the dispatcher
    packet_queue = get_packet_queue(client_key)
    
    print(f"[Streap_raw] run_conn_recv: Starting receive loop for {client_ip}:{client_port} (waiting for data...)")
    
    try:
        while True:
            # Get packet from the dispatcher queue instead of reading directly from socket
            try:
                packet, _addr = packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # Extract IP Header Length
            ihl = (packet[0] & 0x0F) * 4
            tcp_packet = packet[ihl:]
            
            if len(tcp_packet) < 20:
                continue

            # Unpack the received TCP header
            tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
            src_port, dest_port, pkt_seq, pkt_ack, flags = (
                tcph[0],
                tcph[1],
                tcph[2],
                tcph[3],
                tcph[5],
            )

            # Bypass non-listen port
            if dest_port != listen_port:
                continue

            # Check if this packet is for our connection
            if src_port != client_port:
                continue
            
            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4
            psh_flag = (flags & 0x08) >> 3
            fin_flag = (flags & 0x01)
            rst_flag = (flags & 0x04) >> 2

            print(f"[Streap_raw] run_conn_recv: Received packet from {client_ip}:{client_port} (SYN={syn_flag}, ACK={ack_flag}, PSH={psh_flag}, FIN={fin_flag}, RST={rst_flag}, Seq={pkt_seq}, Ack={pkt_ack})")

            with connections_lock:
                if client_key not in connections:
                    continue
                session = connections[client_key]

            # Handle FIN (connection close)
            if fin_flag:
                print(f"[Streap_raw] Received FIN from {client_ip}:{client_port}")
                # Send ACK for FIN
                ack_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                              seq=session.server_seq, ack_seq=pkt_seq + 1, ack=1)
                ip_header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, len(ack_packet))
                s.sendto(ip_header + ack_packet, (client_ip, 0))
                
                with connections_lock:
                    connections.pop(client_key, None)
                # Clean up packet queue
                remove_packet_queue(client_key)
                return b""

            # Handle RST (connection reset)
            if rst_flag:
                print(f"[Streap_raw] Received RST from {client_ip}:{client_port}")
                with connections_lock:
                    connections.pop(client_key, None)
                # Clean up packet queue
                remove_packet_queue(client_key)
                return b""

            # Update last activity
            with connections_lock:
                if client_key in connections:
                    connections[client_key] = session._replace(last_activity=time.time())

            # Handle data payload (PSH + ACK) or (ACK with data) - Fast path ACK
            # Some clients may not set PSH flag for small requests
            has_data = len(tcp_packet) > ((tcp_packet[12] >> 4) & 0x0F) * 4
            
            if (psh_flag and ack_flag) or (ack_flag and has_data and not syn_flag and not fin_flag and not rst_flag):
                # Dynamically look up header length to bypass any incoming TCP Options
                tcp_header_len = ((tcp_packet[12] >> 4) & 0x0F) * 4
                app_payload = tcp_packet[tcp_header_len:]
                
                if len(app_payload) > 0:
                    print(f"[Streap_raw] Received {len(app_payload)} bytes of data from {client_ip}:{client_port}")
                    print(f"[Streap_raw] Received payload: {app_payload[:100]}...")
                    
                    # Send ACK for received data IMMEDIATELY (fast path)
                    next_ack = pkt_seq + len(app_payload)
                    
                    ack_packet = build_tcp_packet(session.server_ip, client_ip, listen_port, client_port,
                                                  seq=session.server_seq, ack_seq=next_ack, ack=1)
                    ip_header = build_ip_header(session.server_ip, client_ip, socket.IPPROTO_TCP, len(ack_packet))
                    s.sendto(ip_header + ack_packet, (client_ip, 0))
                    print(f"[Streap_raw] Sent ACK for data (Ack={next_ack})")
                    
                    # Update sequence numbers AFTER ACK sent
                    with connections_lock:
                        if client_key in connections:
                            connections[client_key] = session._replace(
                                server_seq=session.server_seq,
                                client_seq=next_ack,
                                last_activity=time.time()
                            )
                        
                    # Return the received payload
                    return app_payload

            # Handle pure ACK (no data)
            elif ack_flag and not syn_flag and not psh_flag and not has_data:
                print(f"[Streap_raw] Received ACK from {client_ip}:{client_port} (Ack={pkt_ack})")
                with connections_lock:
                    if client_key in connections:
                        connections[client_key] = session._replace(
                            server_seq=pkt_ack,
                            last_activity=time.time()
                        )

    except KeyboardInterrupt:
        print("\n[Streap_raw] Receive loop interrupted.")
        return b""
    except Exception as e:
        print(f"[Streap_raw] Error in run_conn_recv: {e}")
        return b""


def run_conn_send(s: socket.socket, conn_info: conn_struct, payload: bytes) -> int:
    """
    Send data on an established connection using raw sockets.
    
    Args:
        s: Raw socket
        conn_info: conn_struct tuple for the connection
        payload: Bytes payload to send
    
    Returns:
        int: Number of bytes sent, or -1 on error
    """
    client_ip = conn_info.client_ip
    client_port = conn_info.client_port
    client_key = (client_ip, client_port)
    listen_ip = conn_info.server_ip
    listen_port = conn_info.server_port
    
    with connections_lock:
        if client_key not in connections:
            print(f"[Streap_raw] run_conn_send Connection not found for {client_ip}:{client_port}")
            return -1
        session = connections[client_key]
    
    try:
        bytes_sent = send_tcp_data_segment(
            s, listen_ip, client_ip, listen_port, client_port,
            seq=session.server_seq, ack_seq=session.client_seq, payload=payload
        )
        
        print(f"[Streap_raw] run_conn_send Sent {bytes_sent} bytes to {client_ip}:{client_port}")
        
        # Update sequence numbers
        with connections_lock:
            if client_key in connections:
                connections[client_key] = session._replace(
                    server_seq=session.server_seq + bytes_sent,
                    last_activity=time.time()
                )
        
        return bytes_sent
        
    except Exception as e:
        print(f"[Streap_raw] run_conn_send Error in run_conn_send: {e}")
        return -1


def close_connection(s: socket.socket, conn_info: conn_struct):
    """Close a specific connection by sending FIN and removing from connection table."""
    client_ip = conn_info.client_ip
    client_port = conn_info.client_port
    client_key = (client_ip, client_port)
    listen_ip = conn_info.server_ip
    listen_port = conn_info.server_port
    
    with connections_lock:
        if client_key in connections:
            session = connections[client_key]
            # Send FIN packet
            fin_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                          seq=session.server_seq, ack_seq=session.client_seq, ack=1, fin=1)
            ip_header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, len(fin_packet))
            s.sendto(ip_header + fin_packet, (client_ip, 0))
            print(f"[Streap_raw] run_conn_send: Send FIN to {client_ip}:{client_port}")
            del connections[client_key]
    
    # Clean up packet queue
    remove_packet_queue(client_key)


def close_all_connections():
    """Close all connections and clean up."""
    with connections_lock:
        connections.clear()
