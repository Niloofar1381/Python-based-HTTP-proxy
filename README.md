
````markdown
# Python-based HTTP Proxy

A Python-based HTTP proxy that forwards, caches, and blocks HTTP requests using socket programming. This project supports both a **Command-Line Interface (CLI)** and a **Graphical User Interface (GUI)** using Tkinter.

---

## Table of Contents

- [Features](#features)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Usage](#usage)  
  - [CLI Version](#cli-version)  
  - [GUI Version](#gui-version)  
- [License](#license)

---

## Features

- **Proxy server** with socket programming
- **Caching** of responses for performance (persisted to `cache.pkl`)
- **Blocklist** support via `blocked_urls.txt`
- **Traceroute utility** using system's `tracert` (Windows)
- **Logging** (console for CLI; live text area in GUI)
- **Tkinter GUI** with real-time monitoring and controls

---

## Requirements

- Python 3.x
- No third-party packages — all standard libraries (`socket`, `threading`, `pickle`, `tkinter`, etc.)

---

## Installation

```bash
git clone https://github.com/Niloofar1381/Python-based-HTTP-proxy.git
cd Python-based-HTTP-proxy
````

---

## Usage

### CLI Version (`smart_proxy.py`)

Run the script from the terminal:

```bash
python smart_proxy.py
```

At the prompt, enter any of the following commands:

```
start proxy          # Launch the proxy server (you'll be prompted for a port)
stop proxy           # Stop the currently running proxy server
load blocked urls    # Load the blocklist from 'blocked_urls.txt'
clear blocked urls   # Clear the in-memory blocklist
clear cache          # Clear all cached responses and delete 'cache.pkl'
print cache          # Display currently cached URLs
tracert <host> <max_hops>  # Run a traceroute to a specific host (Windows only)
```

Any invalid command will show a message listing the available commands.

---

### GUI Version (`smart_proxy_gui.py`)

Run the GUI version with:

```bash
python smart_proxy_gui.py
```

#### Features:

* **Start/Stop Proxy**: Enter a port and control the proxy server.
* **Blocked URLs**:

  * Load hosts from `blocked_urls.txt`
  * Clear all blocked hosts
* **Cache**:

  * Clear in-memory and on-disk cache
  * Refresh cache list view
* **Traceroute**:

  * Enter host and max hops
  * View output directly in the log window
* **Live Logging**: All actions and proxy logs appear in a scrollable log window.

---


## Acknowledgments

Inspired by educational projects that explore networking, proxy behavior, and caching in Python.

```

---
