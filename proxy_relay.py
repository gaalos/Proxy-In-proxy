import socket
import ssl
import threading
import urllib.request
import sys
import argparse
import base64
import time

# -----------------------
# --- ARGUMENTS CLI ---
# -----------------------
parser = argparse.ArgumentParser(description="HTTP Proxy Relay with Auth and TLS support")
parser.add_argument("--http-port", type=int, default=8080, help="Local HTTP listening port")
parser.add_argument("--relay-host", type=str, required=True, help="HTTP(S) relay host")
parser.add_argument("--relay-port", type=int, default=443, help="Relay port (443 if TLS)")
parser.add_argument("--relay-tls", action="store_true", help="Use TLS to connect to relay")
parser.add_argument("--relay-user", type=str, help="Relay login username")
parser.add_argument("--relay-pass", type=str, help="Relay login password")
parser.add_argument("--debug-transit", action="store_true", help="Debug relay traffic")
args = parser.parse_args()

LOCAL_PORT = args.http_port
RELAY_HOST = args.relay_host
RELAY_PORT = args.relay_port
USE_TLS = args.relay_tls
RELAY_USER = args.relay_user
RELAY_PASS = args.relay_pass
DEBUG = args.debug_transit

# -----------------------
# --- SYSTEM PROXY ---
# -----------------------
def get_system_proxy():
    try:
        proxy = urllib.request.getproxies().get('http')
        if proxy:
            if proxy.startswith('http://'):
                proxy = proxy[7:]
            host, port = proxy.split(':')
            return host, int(port)
    except:
        pass
    return None, None

SYS_PROXY_HOST, SYS_PROXY_PORT = get_system_proxy()
if SYS_PROXY_HOST:
    print(f"[INFO] System proxy detected: {SYS_PROXY_HOST}:{SYS_PROXY_PORT}")
else:
    print("[INFO] No system proxy detected")

# -----------------------
# --- RELAY TEST ---
# -----------------------
def test_relay():
    try:
        # Connexion vers le proxy système ou directement vers le relais
        target_host = SYS_PROXY_HOST or RELAY_HOST
        target_port = SYS_PROXY_PORT or RELAY_PORT
        sock = socket.create_connection((target_host, target_port), timeout=5)

        # Si le proxy système existe et qu'on veut TLS sur le relais
        if SYS_PROXY_HOST and USE_TLS:
            # CONNECT vers le relais
            connect_req = f"CONNECT {RELAY_HOST}:{RELAY_PORT} HTTP/1.1\r\nHost: {RELAY_HOST}:{RELAY_PORT}\r\nConnection: close\r\n"
            if RELAY_USER and RELAY_PASS:
                auth_str = f"{RELAY_USER}:{RELAY_PASS}"
                auth_enc = base64.b64encode(auth_str.encode()).decode()
                connect_req += f"Proxy-Authorization: Basic {auth_enc}\r\n"
            connect_req += "\r\n"

            sock.sendall(connect_req.encode())
            resp = sock.recv(4096).decode()
            if "200" not in resp:
                print(f"[❌] CONNECT via system proxy failed: {resp.strip()}")
                return False

            # Wrap TLS après CONNECT
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=RELAY_HOST, do_handshake_on_connect=True)

        elif USE_TLS:
            # Pas de proxy système, TLS direct
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=RELAY_HOST, do_handshake_on_connect=True)

        # Test simple : GET ifconfig.me
        http_req = f"GET / HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n"
        sock.sendall(http_req.encode())
        resp = sock.recv(4096).decode(errors='ignore')
        sock.close()

        if "HTTP" in resp:
            if DEBUG:
                print("[✅] Relay test OK")
            return True
        else:
            print("[❌] Relay response invalid")
            return False

    except Exception as e:
        print("[❌] Relay test error:", e)
        return False

if not test_relay():
    print("[ERROR] Aborting: proxy relay not reachable")
    sys.exit(1)

# -----------------------
# --- RELAY HANDLER ---
# -----------------------
def handle_client(client_sock, client_addr):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_host = SYS_PROXY_HOST or RELAY_HOST
        target_port = SYS_PROXY_PORT or RELAY_PORT
        server_sock.connect((target_host, target_port))

        # TLS vers le relais si demandé
        if SYS_PROXY_HOST and USE_TLS:
            # CONNECT via proxy système
            connect_req = f"CONNECT {RELAY_HOST}:{RELAY_PORT} HTTP/1.1\r\nHost: {RELAY_HOST}:{RELAY_PORT}\r\nConnection: close\r\n"
            if RELAY_USER and RELAY_PASS:
                auth_str = f"{RELAY_USER}:{RELAY_PASS}"
                auth_enc = base64.b64encode(auth_str.encode()).decode()
                connect_req += f"Proxy-Authorization: Basic {auth_enc}\r\n"
            connect_req += "\r\n"
            server_sock.sendall(connect_req.encode())
            resp = server_sock.recv(4096)
            if DEBUG:
                print(f"[{client_addr}] CONNECT via system proxy response: {resp[:100]!r}")
            # Wrap TLS après CONNECT
            context = ssl.create_default_context()
            server_sock = context.wrap_socket(server_sock, server_hostname=RELAY_HOST, do_handshake_on_connect=True)
        elif USE_TLS:
            context = ssl.create_default_context()
            server_sock = context.wrap_socket(server_sock, server_hostname=RELAY_HOST, do_handshake_on_connect=True)

        if DEBUG:
            print(f"[{client_addr}] Connected to relay {RELAY_HOST}:{RELAY_PORT}")

        auth_header = None
        if RELAY_USER and RELAY_PASS:
            auth_str = f"{RELAY_USER}:{RELAY_PASS}"
            auth_enc = base64.b64encode(auth_str.encode()).decode()
            auth_header = f"Proxy-Authorization: Basic {auth_enc}\r\n"

        def relay(src, dst, direction):
            nonlocal auth_header
            while True:
                try:
                    data = src.recv(8192)
                    if not data:
                        break
                    # Inject auth only in the first client request
                    if auth_header and direction == "Client→Relay":
                        data_str = data.decode(errors='ignore')
                        if "\r\n\r\n" in data_str:
                            headers, rest = data_str.split("\r\n\r\n", 1)
                            headers += "\r\n" + auth_header
                            data = (headers + "\r\n\r\n" + rest).encode()
                            auth_header = None
                    dst.sendall(data)
                    if DEBUG:
                        print(f"[{client_addr}] {direction}: {len(data)} bytes")
                except:
                    break

        t1 = threading.Thread(target=relay, args=(client_sock, server_sock, "Client→Relay"))
        t2 = threading.Thread(target=relay, args=(server_sock, client_sock, "Relay→Client"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client_sock.close()
        server_sock.close()
    except Exception as e:
        print(f"[{client_addr}] Relay error:", e)
        client_sock.close()
        if 'server_sock' in locals():
            server_sock.close()

# -----------------------
# --- LISTENER ---
# -----------------------
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('', LOCAL_PORT))
listener.listen(50)
print(f"[INFO] Local HTTP relay listening on {LOCAL_PORT}")

# -----------------------
# --- RELAY WATCHDOG ---
# -----------------------
def relay_watchdog():
    while True:
        if not test_relay():
            print("[⚠] Relay failed, check connection!")
        time.sleep(10)

threading.Thread(target=relay_watchdog, daemon=True).start()

while True:
    try:
        client, addr = listener.accept()
        if DEBUG:
            print(f"[INFO] New client: {addr}")
        t = threading.Thread(target=handle_client, args=(client, addr))
        t.start()
    except KeyboardInterrupt:
        print("Shutting down...")
        listener.close()
        break