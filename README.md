# 🦅 ShadowRaven – HTTP Packet Sniffer

**ShadowRaven** is a lightweight HTTP packet sniffer built using Python and Scapy.  
It captures HTTP traffic on a given interface, extracts method, host, path and searches for sensitive data like passwords, tokens, emails, and more.  
It’s designed for educational and testing purposes, and includes a little flair with a crow ASCII logo.

---

## 💡 Features

- Live sniffing of HTTP requests
- Displays request method, host, and path
- Scans HTTP payloads for sensitive keywords
- Colorful terminal output using `termcolor`
- Crow-themed banner 🐦

---

## 📦 Requirements

- Python 3.x
- [Scapy](https://pypi.org/project/scapy/)
- [termcolor](https://pypi.org/project/termcolor/)

Install dependencies:

```bash
pip install scapy termcolor
```

⚙️ Usage
Run the script with root privileges (required for packet sniffing):
```bash
sudo python3 shadowraven.py -i <interface>
```
Replace <interface> with your network interface (like eth0, wlan0, enp0s3, etc.)
```bash
sudo python3 shadowraven.py -i wlan0
```

⚠️ Disclaimer
ShadowRaven is intended for educational purposes only.
Do NOT use this tool on networks or devices without explicit authorization.
Unauthorized sniffing may be illegal and is not condoned.
