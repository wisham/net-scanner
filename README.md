# net-scanner

# 🛡️ Network Scanner & Web Footprinting Tool (Tkinter GUI)

A complete ethical hacking utility built in Python with a beautiful Tkinter-based GUI. This tool allows you to perform various footprinting and scanning tasks on a given IP or domain such as WHOIS lookup, DNS analysis, subdomain enumeration, port scanning, and more — all within an intuitive, user-friendly interface.

-----------------------------------------------------------------------------------------

## ✨ Features

- 🌐 **WHOIS Lookup**
- 🧭 **DNS Lookup**
- 🌍 **Subdomain Finder**
- 🚪 **Port Scanner**
- 🔎 **Banner Grabber**
- 🕵️‍♂️ **Robots.txt Checker**
- ⚙️ **HTTP Headers Viewer**
- 📶 **Traceroute**
- 📡 **Ping Sweep**
- 🧩 **CMS Detector (Basic)**

-----------------------------------------------------------------------------------------



## 🛠️ Technologies Used

- Python 3
- **Tkinter** – for GUI
- **Requests, dnspython, whois** – for various scanners

-----------------------------------------------------------------------------------------

## 🚀 How to Run

1. Clone the Repository
```bash
git clone https://github.com/wisham/net-scanner.git
cd network-scanner-gui


-----------------------------------------------------------------------------------------
Extract .rar File

1.INSTALLATION
    sudo apt update
    sudo apt install unrar -y

2. To extract to the same directory:
    unrar x scanners.rar

-----------------------------------------------------------------------------------------

Run the App
  python main_gui.py
-----------------------------------------------------------------------------------------

Folder Structure
network-scanner-gui/
├── main_gui.py
├── scanners/
│   ├── banner_grabber.py
│   ├── cms_detector.py
│   ├── dns_lookup.py
│   ├── http_headers.py
│   ├── ping_sweep.py
│   ├── port_scanner.py
│   ├── robots_checker.py
│   ├── subdomain_finder.py
│   ├── traceroute.py
│   └── whois_lookup.py
