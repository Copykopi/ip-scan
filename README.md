# IP SCAN TOOLS BY Nyx 
A powerful network scanner built with Python, Scapy, and Colorama.
This tool performs ARP scans to discover hosts, TCP SYN scans for ports, and grabs banners/OS info.

## Features
- **Host Discovery:** Finds all active devices on the network using ARP scan.
- **Vendor Detection:** Identifies the device manufacturer (e.g., Apple, Samsung) from its MAC address.
- **Port Scanning:** Uses stealthy TCP SYN scan to find open ports.
- **Service & OS Detection:** Identifies services (HTTP, SSH) and guesses the OS (Windows/Linux) via TTL.
- **Banner Grabbing:** "Intips" open ports to get service version info (e.g., `Apache/2.4.52`).
- **Cool UI:** Modern, colorized output for easy reading.

## Installation
1.  Clone this repository:
    ```bash
    https://github.com/Nyx-Developer/ip-scan.git
    ```
2.  Install required libraries:
    ```bash
    pip install scapy requests colorama
    ```

## How to Use
This script requires root/administrator privileges to run (for ARP and SYN scans).

**Linux / macOS:**
```bash
sudo python3 ipscan.py
