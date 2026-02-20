git clone https://github.com/gaalos/Proxy-In-proxy.git

python.exe proxy_relay.py --http-port 8088 --relay-host RELAY --relay-port 443 --relay-tls --relay-user XXX --relay-pass XX





usage: proxy_relay.py [-h] [--http-port HTTP_PORT] --relay-host RELAY_HOST [--relay-port RELAY_PORT] [--relay-tls]
                      [--relay-user RELAY_USER] [--relay-pass RELAY_PASS] [--debug-transit]

HTTP Proxy Relay

options:
  -h, --help            show this help message and exit
  --http-port HTTP_PORT
  --relay-host RELAY_HOST
  --relay-port RELAY_PORT
  --relay-tls
  --relay-user RELAY_USER
  --relay-pass RELAY_PASS
  --debug-transit
