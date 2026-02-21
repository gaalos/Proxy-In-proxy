import asyncio
import ssl
import base64
import argparse
import urllib.request
import socket

parser = argparse.ArgumentParser(description="Async HTTP/HTTPS Proxy Relay (Windows proxy compatible)")
parser.add_argument("--http-port", type=int, default=8080)
parser.add_argument("--relay-host", type=str, required=True)
parser.add_argument("--relay-port", type=int, default=443)
parser.add_argument("--relay-tls", action="store_true")
parser.add_argument("--relay-user", type=str)
parser.add_argument("--relay-pass", type=str)
parser.add_argument("--debug-transit", action="store_true")
parser.add_argument("--timeout", type=int, default=60)
args = parser.parse_args()

LOCAL_PORT = args.http_port
RELAY_HOST = args.relay_host
RELAY_PORT = args.relay_port
USE_TLS = args.relay_tls
RELAY_USER = args.relay_user
RELAY_PASS = args.relay_pass
DEBUG = args.debug_transit
TIMEOUT = args.timeout

# ---------------- SYSTEM PROXY ----------------
def get_system_proxy():
    try:
        proxy = urllib.request.getproxies().get("http")
        if proxy:
            if proxy.startswith("http://"):
                proxy = proxy[7:]
            host, port = proxy.split(":")
            return host, int(port)
    except:
        pass
    return None, None

SYS_PROXY_HOST, SYS_PROXY_PORT = get_system_proxy()
if SYS_PROXY_HOST:
    print(f"[INFO] System proxy detected: {SYS_PROXY_HOST}:{SYS_PROXY_PORT}")
else:
    print("[INFO] No system proxy detected")

# ---------------- CONNECT TO RELAY ----------------
async def connect_to_relay():
    auth_header = None
    ssl_context = ssl.create_default_context() if USE_TLS else None

    if RELAY_USER and RELAY_PASS:
        auth_enc = base64.b64encode(f"{RELAY_USER}:{RELAY_PASS}".encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {auth_enc}\r\n"

    if SYS_PROXY_HOST:
        # 1️⃣ Connect to system proxy
        raw_sock = socket.create_connection((SYS_PROXY_HOST, SYS_PROXY_PORT), timeout=10)
        raw_sock.setblocking(True)

        # 2️⃣ Send CONNECT
        connect_req = f"CONNECT {RELAY_HOST}:{RELAY_PORT} HTTP/1.1\r\nHost: {RELAY_HOST}:{RELAY_PORT}\r\n\r\n"
        raw_sock.sendall(connect_req.encode())

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw_sock.recv(4096)
            if not chunk:
                break
            resp += chunk

        if b"200" not in resp:
            raw_sock.close()
            raise ConnectionError(f"Proxy CONNECT failed:\n{resp.decode(errors='ignore')}")
        if DEBUG:
            print("[DEBUG] CONNECT via system proxy OK")

        # 3️⃣ Wrap TLS via asyncio (if needed)
        if USE_TLS:
            reader, writer = await asyncio.open_connection(sock=raw_sock, ssl=ssl_context, server_hostname=RELAY_HOST)
        else:
            reader, writer = await asyncio.open_connection(sock=raw_sock)
    else:
        # Direct connection to relay
        reader, writer = await asyncio.open_connection(RELAY_HOST, RELAY_PORT, ssl=ssl_context, server_hostname=RELAY_HOST if USE_TLS else None)

    return reader, writer, auth_header

# ---------------- RELAY HANDLER ----------------
async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    first_packet = True
    relay_reader = relay_writer = None
    try:
        relay_reader, relay_writer, auth_header = await connect_to_relay()

        async def pipe(src, dst, direction):
            nonlocal first_packet, auth_header
            while True:
                try:
                    data = await asyncio.wait_for(src.read(16*1024), timeout=TIMEOUT)
                    if not data:
                        break
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
                    dst.write(data)
                    await dst.drain()
                    if DEBUG:
                        print(f"[{addr}] {direction}: {len(data)} bytes")
                except asyncio.TimeoutError:
                    break
                except Exception:
                    break

        await asyncio.gather(
            pipe(reader, relay_writer, "Client→Relay"),
            pipe(relay_reader, writer, "Relay→Client")
        )
    except Exception as e:
        print(f"[{addr}] Relay error: {e}")
    finally:
        try: writer.close(); await writer.wait_closed()
        except: pass
        try:
            if relay_writer:
                relay_writer.close(); await relay_writer.wait_closed()
        except: pass

# ---------------- RELAY WATCHDOG ----------------
async def relay_watchdog():
    while True:
        try:
            r, w, _ = await connect_to_relay()
            w.close()
            await w.wait_closed()
            if DEBUG:
                print("[✅] Relay test OK")
        except Exception as e:
            print(f"[⚠] Relay failed: {e}")
        await asyncio.sleep(10)

# ---------------- MAIN ----------------
async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LOCAL_PORT)
    print(f"[INFO] Async relay listening on port {LOCAL_PORT}")
    asyncio.create_task(relay_watchdog())
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down...")
