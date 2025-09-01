# Python-based HTTP Proxy

A Python-based HTTP proxy that forwards, caches, and blocks HTTP requests using socket programming. It offers both a CLI version and a GUI version (Tkinter), each with their own command/control interface.

---

##  Table of Contents

- [Features](#features)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Usage](#usage)  
  - [CLI Version](#cli-version)  
  - [GUI Version](#gui-version)  
- [Commands & Controls](#commands--controls)  
- [License](#license)

---

##  Features

- **HTTP proxy**: Forwards client HTTP requests to upstream servers.
- **Caching**: Stores responses in memory and on disk (`cache.pkl`) to reduce redundant requests.
- **Blocking**: Supports host-based blocking via `blocked_urls.txt`.
- **Traceroute utility**: Runs `tracert` (Windows) to debug network routes.
- **Logging**:
  - CLI: Logs printed to console.
  - GUI: Logs displayed in a scrollable text area.
- **Two Interfaces**:
  - **CLI** mode: Interactive prompts and commands.
  - **GUI** mode: Tkinter-based graphical interface for controls and monitoring.

---

##  Requirements

- **Python 3.x**
- Standard Python libraries only: `socket`, `threading`, `pickle`, `os`, `re`, `struct`, `subprocess`, `tkinter` (for GUI), `queue`.

---

##  Installation

Clone the repository:

```bash
git clone https://github.com/Niloofar1381/Python-based-HTTP-proxy.git
cd Python-based-HTTP-proxy
````

No additional dependencies are needed—everything runs using the Python standard library.


## Usage

### CLI Version (`smart_proxy.py` or similar)

1. **Start the script**:

   ```bash
   python smart_proxy.py
   ```

2. **At the prompt**, type one of the following commands:

   * `start proxy`: Launch the proxy. You'll be prompted for a port number.
   * `stop proxy`: Stop the running proxy.
   * `load blocked urls`: Reload the blocklist from `blocked_urls.txt`.
   * `clear blocked urls`: Clear all blocked hosts.
   * `clear cache`: Clear cached responses in memory and delete the `cache.pkl` file.
   * `print cache`: Display all cached URLs.
   * `tracert <host> <max_hops>`: Run a traceroute to the specified host (Windows-only).
   * Any unrecognized command displays a help message with valid options.

### GUI Version (`smart_proxy_gui.py` or similar)

1. **Start the GUI**:

   ```bash
   python smart_proxy_gui.py
   ```

2. **Interface Overview**:

   * **Proxy Controls**:

     * Set port and click **"Start Proxy"** or **"Stop Proxy"**.
   * **Blocked URLs**:

     * Click **"Load Blocked"** to import `blocked_urls.txt`.
     * Click **"Clear Blocked"** to reset the list.
     * Hosts appear in the list box for review.
   * **Cache Controls**:

     * **"Clear Cache"**: Remove all cached data and delete the file.
     * **"Refresh Cache"**: Reload the cache list display.
     * Cached entries appear as URLs in the cache list box.
   * **Traceroute**:

     * Enter a host and maximum hops, then click **"Run Tracert"** to initiate.
   * **Log Area**:

     * Displays live logs from proxy activity, block events, traceroute output, etc.

---

## Commands & Controls Quick Reference

| Version | Command / Button     | Description                                    |
| ------- | -------------------- | ---------------------------------------------- |
| CLI     | `start proxy`        | Prompts for port, then starts the proxy        |
| CLI     | `stop proxy`         | Stops the running proxy                        |
| CLI     | `load blocked urls`  | Loads hosts to block from `blocked_urls.txt`   |
| CLI     | `clear blocked urls` | Clears the block list                          |
| CLI     | `clear cache`        | Clears in-memory cache and deletes `cache.pkl` |
| CLI     | `print cache`        | Lists all cached URLs                          |
| CLI     | `tracert host hops`  | Runs Windows `tracert` with max hops           |
| GUI     | **"Start Proxy"**    | Start proxy on specified port                  |
| GUI     | **"Stop Proxy"**     | Stop proxy                                     |
| GUI     | **"Load Blocked"**   | Import blocked URLs list                       |
| GUI     | **"Clear Blocked"**  | Clear blocklist                                |
| GUI     | **"Clear Cache"**    | Reset cache and delete file                    |
| GUI     | **"Refresh Cache"**  | Refresh cache list display                     |
| GUI     | **"Run Tracert"**    | Execute traceroute with given host and hops    |

---
