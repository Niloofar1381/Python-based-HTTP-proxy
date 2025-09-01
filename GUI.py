import socket
import threading
import struct
import re
import pickle
import os
import sys
import time
import subprocess
import tkinter as tk
from tkinter import messagebox, scrolledtext
import queue

BUFFER_SIZE = 4096
blocked_hosts = set()
cache = {} # key: (host, path), value: response bytes
CACHE_FILE = "cache.pkl"
proxy = None
proxy_thread = None
log_queue = queue.Queue()

def log(message):
    log_queue.put(message)

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
                        log(f"[Blocklist] Loaded ({idx+1}): '{host}'")
                        hosts.add(host)
    except Exception as e:
        log(f"Could not load blocked URLs: {e}")
    return hosts

def clear_blocked_urls():
    global blocked_hosts
    blocked_hosts.clear()
    log("Blocked URLs cleared.")

def save_cache():
    try:
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(cache, f)
        log("[CACHE] Cache saved to disk.")
    except Exception as e:
        log(f"[CACHE] Error saving cache: {e}")

def load_cache():
    global cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                cache = pickle.load(f)
            log(f"[CACHE] Loaded {len(cache)} cached items from disk.")
        except Exception as e:
            log(f"[CACHE] Error loading cache: {e}")
            cache = {}
    else:
        cache = {}
        log("[CACHE] No cache file found; starting with empty cache.")

def clear_cache():
    global cache
    cache.clear()
    if os.path.exists(CACHE_FILE):
        try:
            os.remove(CACHE_FILE)
            log("[CACHE] Cache file removed from disk.")
        except Exception as e:
            log(f"[CACHE] Error removing cache file: {e}")
    log("Cache cleared.")

def tracert(dest_name, max_hops=5, timeout=2):
    log(f"Tracing route to {dest_name} over a maximum of {max_hops} hops:")
    # Remove protocol (http:// or https://) if present
    dest_name = extract_host(dest_name)
    try:
        dest_addr = socket.gethostbyname(dest_name)
        log(f"Destination IP: {dest_addr}")
    except Exception as e:
        log(f"Unable to resolve {dest_name}: {e}")
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
        log(result.stdout)
    except Exception as e:
        log(f"Error running system tracert: {e}")

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
        log(f"[*] Proxy Server started on {self.server_host}:{self.server_port}")
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
                log(f"Failed to set SO_LINGER: {e}")
            self.server_socket.close()
        log("[*] Proxy Server stopped.")

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
                log("[!] HTTPS not supported. Rejecting CONNECT method.")
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
            log(f"[Proxy] Requested host: '{cleaned_webserver}'")
            if cleaned_webserver in blocked_hosts:
                log(f"[BLOCKED] '{cleaned_webserver}' is BLOCKED.")
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
                log(f"[Proxy] '{cleaned_webserver}' is allowed.")
            # === CACHE LOGIC ===
            cache_key = (cleaned_webserver, path)
            if cache_key in cache:
                log(f"Using cached response for http://{cleaned_webserver}{path}")
                client_socket.sendall(cache[cache_key])
                client_socket.close()
                return
            else:
                log(f"[CACHE] Cache miss for ({cleaned_webserver}, {path})")
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
            log(f"[!] Error: {e}")
            client_socket.close()

def on_start_proxy():
    global proxy, proxy_thread
    if proxy and proxy.running:
        log("Proxy is already running.")
        return
    try:
        port = int(port_entry.get())
    except ValueError:
        log("Invalid port.")
        return
    proxy = HTTPProxyServer(port=port)
    proxy_thread = threading.Thread(target=proxy.start)
    proxy_thread.daemon = True
    proxy_thread.start()
    log("Proxy started.")

def on_stop_proxy():
    global proxy, proxy_thread
    if not proxy or not proxy.running:
        log("Proxy is not running.")
        return
    proxy.stop()
    if proxy_thread:
        proxy_thread.join()
    log("Proxy stopped.")
    proxy = None

def on_load_blocked():
    global blocked_hosts
    blocked_hosts = load_blocked_urls()
    update_blocked_list()
    log(f"Blocked URLs reloaded. {len(blocked_hosts)} hosts loaded.")

def on_clear_blocked():
    clear_blocked_urls()
    update_blocked_list()

def on_clear_cache():
    clear_cache()
    update_cache_list()

def on_refresh_cache():
    update_cache_list()

def on_tracert():
    host = host_entry.get().strip()
    if not host:
        log("Please enter a host.")
        return
    try:
        hops = int(hops_entry.get())
    except ValueError:
        log("Invalid max hops.")
        return
    tracert(host, hops)

def update_blocked_list():
    blocked_listbox.delete(0, tk.END)
    for host in sorted(blocked_hosts):
        blocked_listbox.insert(tk.END, host)

def update_cache_list():
    cache_listbox.delete(0, tk.END)
    for host_path in sorted(cache.keys()):
        host, path = host_path
        url = f"http://{host}{path}"
        cache_listbox.insert(tk.END, url)

def check_queue():
    while True:
        try:
            msg = log_queue.get_nowait()
            log_text.insert(tk.END, msg + '\n')
            log_text.see(tk.END)
        except queue.Empty:
            break
    root.after(100, check_queue)

if __name__ == "__main__":
    load_cache()

    root = tk.Tk()
    root.title("HTTP Proxy GUI")

    # Proxy control
    proxy_frame = tk.Frame(root)
    proxy_frame.pack(pady=10)
    tk.Label(proxy_frame, text="Port:").pack(side=tk.LEFT, padx=5)
    port_entry = tk.Entry(proxy_frame)
    port_entry.insert(0, "8080")
    port_entry.pack(side=tk.LEFT, padx=5)
    tk.Button(proxy_frame, text="Start Proxy", command=on_start_proxy).pack(side=tk.LEFT, padx=5)
    tk.Button(proxy_frame, text="Stop Proxy", command=on_stop_proxy).pack(side=tk.LEFT, padx=5)

    # Blocked URLs
    blocked_frame = tk.Frame(root)
    blocked_frame.pack(pady=10)
    tk.Label(blocked_frame, text="Blocked URLs").pack()
    blocked_listbox = tk.Listbox(blocked_frame, height=10, width=50)
    blocked_listbox.pack(side=tk.LEFT, padx=5)
    blocked_btn_frame = tk.Frame(blocked_frame)
    blocked_btn_frame.pack(side=tk.LEFT, padx=5)
    tk.Button(blocked_btn_frame, text="Load Blocked", command=on_load_blocked).pack(pady=5)
    tk.Button(blocked_btn_frame, text="Clear Blocked", command=on_clear_blocked).pack(pady=5)

    # Cache
    cache_frame = tk.Frame(root)
    cache_frame.pack(pady=10)
    tk.Label(cache_frame, text="Cache").pack()
    cache_listbox = tk.Listbox(cache_frame, height=10, width=50)
    cache_listbox.pack(side=tk.LEFT, padx=5)
    cache_btn_frame = tk.Frame(cache_frame)
    cache_btn_frame.pack(side=tk.LEFT, padx=5)
    tk.Button(cache_btn_frame, text="Clear Cache", command=on_clear_cache).pack(pady=5)
    tk.Button(cache_btn_frame, text="Refresh Cache", command=on_refresh_cache).pack(pady=5)

    # Tracert
    tracert_frame = tk.Frame(root)
    tracert_frame.pack(pady=10)
    tk.Label(tracert_frame, text="Tracert Host:").pack(side=tk.LEFT, padx=5)
    host_entry = tk.Entry(tracert_frame, width=30)
    host_entry.pack(side=tk.LEFT, padx=5)
    tk.Label(tracert_frame, text="Max Hops:").pack(side=tk.LEFT, padx=5)
    hops_entry = tk.Entry(tracert_frame, width=5)
    hops_entry.insert(0, "5")
    hops_entry.pack(side=tk.LEFT, padx=5)
    tk.Button(tracert_frame, text="Run Tracert", command=on_tracert).pack(side=tk.LEFT, padx=5)

    # Log area
    log_text = scrolledtext.ScrolledText(root, height=15, width=80)
    log_text.pack(pady=10)

    check_queue()
    update_blocked_list()
    update_cache_list()

    root.mainloop()