from scapy.all import sniff, IP, Raw
from scapy.layers.http import HTTPRequest
import argparse
from termcolor import colored

# Cute
def print_crow():
    crow = r"""
               ,_,
             (O,O)       
             (   )  <-- ShadowRaven is watching...
             "   "
        ,_,                  ,_,
      (O,O)                (O,O)
      (   )  ShadowRaven   (   )   [Sniffer Loaded]
      " "                  " "
    """
    print(colored(crow, "magenta"))

# Extract HTTP informations
def extract_http_info(packet):
    try:
        #packet.show()
        method = packet[HTTPRequest].Method.decode()
        host = packet[HTTPRequest].Host.decode()
        path = packet[HTTPRequest].Path.decode()
        return method, host, path
    except:
        return None, None, None

# Extract raw datas (aka body)
def extract_raw_data(packet):
    if packet.haslayer(Raw):
        try:
            return packet[Raw].load.decode(errors="ignore").lower()
        except:
            return None
    return None

# Process each packet gotten
def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        method, host, path = extract_http_info(packet)
        if method and host and path:
            print(colored(f"[+] {method} request to {host}{path}", "green"))

        data = extract_raw_data(packet)
        if data:
            keywords = ["password", "username", "user", "login", "token", "mail", "email", "pass"]
            for keyword in keywords:
                if keyword in data:
                    print(colored(f"[+] Possible Data: {data}", "yellow"))
                    break  # para de verificar ao encontrar o primeiro match

# Main function
def main():
    parser = argparse.ArgumentParser(description="Simple HTTP Sniffer with crow 🦅")
    parser.add_argument("-i", "--interface", required=True, help="Network Interface (ex: eth0, enp0s3)")
    args = parser.parse_args()

    print_crow()
    print(colored(f"[~] Sniffing started on interface {args.interface}...\n", "cyan"))
    sniff(iface=args.interface, store=False, prn=process_sniffed_packet)

if __name__ == "__main__":
    main()
