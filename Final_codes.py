import socket
import threading
import struct
import re
import pickle
import os
import sys
import time
import subprocess

BUFFER_SIZE = 4096

blocked_hosts = set()
cache = {}  # key: (host, path), value: response bytes
CACHE_FILE = "cache.pkl"

def extract_host(line):
    line = line.strip()
    line = re.sub(r'^https?://', '', line, flags=re.IGNORECASE)
    line = line.split('/')[0]
    line = re.sub(r'^www\d*\.', '', line, flags=re.IGNORECASE)
    line = line.split(':')[0]
    return line.lower().strip()

def load_blocked_urls(filename='blocked_urls.txt'):
    hosts = set()
    try:
        with open(filename, 'r') as f:
            for idx, line in enumerate(f):
                if line.strip():
                    host = extract_host(line)
                    if host:
                        print(f"[Blocklist] Loaded ({idx+1}): '{host}'")
                        hosts.add(host)
    except Exception as e:
        print(f"Could not load blocked URLs: {e}")
    return hosts

def clear_blocked_urls():
    global blocked_hosts
    blocked_hosts.clear()
    print("Blocked URLs cleared.")

def save_cache():
    try:
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(cache, f)
        print("[CACHE] Cache saved to disk.")
    except Exception as e:
        print(f"[CACHE] Error saving cache: {e}")

def load_cache():
    global cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                cache = pickle.load(f)
            print(f"[CACHE] Loaded {len(cache)} cached items from disk.")
        except Exception as e:
            print(f"[CACHE] Error loading cache: {e}")
            cache = {}
    else:
        cache = {}
        print("[CACHE] No cache file found; starting with empty cache.")

def clear_cache():
    global cache
    cache.clear()
    if os.path.exists(CACHE_FILE):
        try:
            os.remove(CACHE_FILE)
            print("[CACHE] Cache file removed from disk.")
        except Exception as e:
            print(f"[CACHE] Error removing cache file: {e}")
    print("Cache cleared.")

def print_cache():
    if not cache:
        print("Cache is empty.")
    else:
        print("Currently cached URLs:")
        for host, path in cache.keys():
            print(f"  http://{host}{path}")

def tracert(dest_name, max_hops=5, timeout=2):
    print(f"Tracing route to {dest_name} over a maximum of {max_hops} hops:")
    # Remove protocol (http:// or https://) if present
    dest_name = extract_host(dest_name)
    try:
        dest_addr = socket.gethostbyname(dest_name)
        print(f"Destination IP: {dest_addr}")
    except Exception as e:
        print(f"Unable to resolve {dest_name}: {e}")
        return

    # Use Windows tracert via subprocess
    try:
        # -d: do not resolve addresses to hostnames (faster)
        # -h <hops>: maximum hops
        # -w <timeout>: timeout per hop in ms (set to 1000*timeout)
        result = subprocess.run(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout*1000), dest_name],
            capture_output=True, text=True, encoding="utf-8"
        )
        print(result.stdout)
    except Exception as e:
        print("Error running system tracert:", e)

class HTTPProxyServer:
    def __init__(self, host='127.0.0.1', port=8080):
        self.server_host = host
        self.server_port = port
        self.running = False
        self.server_socket = None

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(100)
        self.server_socket.settimeout(1.0)
        print(f"[*] Proxy Server started on {self.server_host}:{self.server_port}")

        while self.running:
            try:
                client_socket, _ = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

        if self.server_socket:
            self.server_socket.close()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            except Exception as e:
                print(f"Failed to set SO_LINGER: {e}")
            self.server_socket.close()
        print("[*] Proxy Server stopped.")

    def recv_request_headers(self, sock):
        sock.settimeout(2)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data

    def sanitize_request(self, request_lines, host):
        sanitized = []
        for line in request_lines:
            if line.lower().startswith(b'connection') or line.lower().startswith(b'proxy-connection') or line.lower().startswith(b'accept-encoding'):
                continue
            if line.lower().startswith(b'host:'):
                continue
            sanitized.append(line)
        sanitized.insert(1, f"Host: {host}".encode())
        sanitized.append(b"Connection: close")
        return b'\r\n'.join(sanitized) + b'\r\n\r\n'

    def handle_client(self, client_socket):
        global blocked_hosts, cache
        try:
            request = self.recv_request_headers(client_socket)
            if not request:
                client_socket.close()
                return

            request_lines = request.split(b'\r\n')
            request_line = request_lines[0].decode(errors='replace')
            method, full_url, protocol = request_line.split()

            if method.upper() == 'CONNECT':
                print("[!] HTTPS not supported. Rejecting CONNECT method.")
                client_socket.close()
                return

            http_pos = full_url.find("://")
            scheme = 'http'
            if http_pos != -1:
                scheme = full_url[:http_pos]
                full_url = full_url[(http_pos + 3):]
            path_pos = full_url.find("/")
            if path_pos == -1:
                path = "/"
                host = full_url
            else:
                path = full_url[path_pos:]
                host = full_url[:path_pos]

            if ':' in host:
                webserver, port = host.split(':')
                port = int(port)
            else:
                webserver = host
                port = 80

            cleaned_webserver = extract_host(webserver)
            print(f"[Proxy] Requested host: '{cleaned_webserver}'")

            if cleaned_webserver in blocked_hosts:
                print(f"[BLOCKED] '{cleaned_webserver}' is BLOCKED.")
                response = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                    "<html><body><h1>Access Denied</h1></body></html>"
                )
                client_socket.sendall(response.encode())
                client_socket.close()
                return
            else:
                print(f"[Proxy] '{cleaned_webserver}' is allowed.")

            # === CACHE LOGIC ===
            cache_key = (cleaned_webserver, path)
            if cache_key in cache:
                print(f"Using cached response for http://{cleaned_webserver}{path}")
                client_socket.sendall(cache[cache_key])
                client_socket.close()
                return
            else:
                print(f"[CACHE] Cache miss for ({cleaned_webserver}, {path})")

            # Forward request to server if not cached
            request_lines[0] = f"{method} {path} {protocol}".encode()
            sanitized_request = self.sanitize_request(request_lines, webserver)

            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.settimeout(5)
            proxy_socket.connect((webserver, port))
            proxy_socket.sendall(sanitized_request)

            response_data = b""
            while True:
                try:
                    data = proxy_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                    response_data += data
                    client_socket.sendall(data)
                except socket.timeout:
                    break

            proxy_socket.close()
            client_socket.close()

            # Store response in cache and save to disk
            cache[cache_key] = response_data
            save_cache()

        except Exception as e:
            print(f"[!] Error: {e}")
            client_socket.close()

if __name__ == "__main__":
    blocked_hosts = set()
    load_cache()  # Load cache from disk at startup

    proxy = None
    proxy_thread = None

    while True:
        command = input("\nType your command: ").strip().lower()

        if command == 'start proxy':
            if proxy and proxy.running:
                print("Proxy is already running.")
                continue
            try:
                port = int(input("Enter port: "))
            except ValueError:
                print("Invalid port.")
                continue
            proxy = HTTPProxyServer(port=port)
            proxy_thread = threading.Thread(target=proxy.start)
            proxy_thread.daemon = True
            proxy_thread.start()

        elif command == 'stop proxy':
            if proxy and proxy.running:
                proxy.stop()
                proxy_thread.join()
                print("Proxy stopped.")
            else:
                print("Proxy is not running.")
        elif command == 'load blocked urls':
            blocked_hosts = load_blocked_urls()
            print(f"Blocked URLs reloaded. {len(blocked_hosts)} hosts loaded.")
        elif command == 'clear blocked urls':
            clear_blocked_urls()
        elif command == 'clear cache':
            clear_cache()
        elif command == 'print cache':
            print_cache()
        elif command.startswith('tracert '):
            parts = command.split()
            if len(parts) == 3:
                _, host, hops = parts
                try:
                    hops = int(hops)
                    tracert(host, hops)
                except ValueError:
                    print("Usage: tracert <host> <max_hops>")
            else:
                print("Usage: tracert <host> <max_hops>")
        else:
            print("Invalid command. Type 'start proxy', 'stop proxy', 'load blocked urls', 'clear blocked urls', 'clear cache', 'print cache', or 'tracert <host> <max_hops>'.")
