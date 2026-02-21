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
parser = argparse.ArgumentParser(description="HTTP Proxy Relay with tunnel-in-tunnel support")
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
# --- CONNECT TO RELAY ---
# -----------------------
def connect_to_relay():
    """Crée un socket vers le relais en passant par le proxy Windows si présent"""
    sock = None
    auth_header = None

    if SYS_PROXY_HOST:
        # 1️⃣ Connexion au proxy Windows
        sock = socket.create_connection((SYS_PROXY_HOST, SYS_PROXY_PORT), timeout=10)

        # 2️⃣ Tunnel vers le relay via CONNECT (fonctionne même si relay HTTP)
        connect_req = f"CONNECT {RELAY_HOST}:{RELAY_PORT} HTTP/1.1\r\nHost: {RELAY_HOST}:{RELAY_PORT}\r\nProxy-Connection: keep-alive\r\n\r\n"
        sock.sendall(connect_req.encode())

        # Lire réponse complète
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        resp_str = response.decode(errors='ignore')
        if "200" not in resp_str:
            raise Exception(f"CONNECT via system proxy failed:\n{resp_str}")

        if DEBUG:
            print("[DEBUG] Tunnel CONNECT via system proxy established")

    else:
        # Connexion directe au relais
        sock = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=10)

    # 3️⃣ Wrap TLS si demandé
    if USE_TLS:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=RELAY_HOST)
        if DEBUG:
            print("[DEBUG] TLS established to relay")

    # 4️⃣ Préparer l’auth si nécessaire
    if RELAY_USER and RELAY_PASS:
        auth_enc = base64.b64encode(f"{RELAY_USER}:{RELAY_PASS}".encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {auth_enc}\r\n"

    return sock, auth_header

# -----------------------
# --- RELAY TEST ---
# -----------------------
def test_relay():
    try:
        sock, auth_header = connect_to_relay()
        req = "GET / HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n"
        if auth_header:
            req += auth_header
        req += "\r\n"
        sock.sendall(req.encode())
        resp = sock.recv(4096).decode(errors='ignore')
        sock.close()

        if "HTTP" in resp:
            if DEBUG:
                print("[✅] Relay test OK")
            return True
        return False

    except Exception as e:
        print("[❌] Relay test error:", e)
        return False

if not test_relay():
    print("[ERROR] Aborting: relay not reachable")
    sys.exit(1)

# -----------------------
# --- RELAY HANDLER ---
# -----------------------
def handle_client(client_sock, client_addr):
    try:
        server_sock, auth_header = connect_to_relay()

        if DEBUG:
            print(f"[{client_addr}] Tunnel ready")

        first_packet = True

        def relay(src, dst, direction):
            nonlocal first_packet, auth_header
            while True:
                try:
                    data = src.recv(8192)
                    if not data:
                        break

                    # Inject auth only on first HTTP request
                    if first_packet and auth_header and direction == "Client→Relay":
                        try:
                            data_str = data.decode(errors="ignore")
                            if "\r\n\r\n" in data_str:
                                headers, rest = data_str.split("\r\n\r\n", 1)
                                headers += "\r\n" + auth_header
                                data = (headers + "\r\n\r\n" + rest).encode()
                                auth_header = None
                        except:
                            pass
                        first_packet = False

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

# -----------------------
# --- MAIN LOOP ---
# -----------------------
while True:
    try:
        client, addr = listener.accept()
        if DEBUG:
            print(f"[INFO] New client: {addr}")
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()
    except KeyboardInterrupt:
        print("Shutting down...")
        listener.close()
        break
