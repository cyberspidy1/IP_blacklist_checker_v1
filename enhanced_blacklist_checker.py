
import socket
from ipwhois import IPWhois, exceptions
import ipaddress
import dns.resolver
import threading
import pandas as pd
import time

dnsbls = [
    "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
    "b.barracudacentral.org", "psbl.surriel.com", "dnsbl-1.uceprotect.net"
]

results = []
lock = threading.Lock()

def reverse_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return '.'.join(reversed(ip.split('.')))
    except Exception:
        return None

def check_blacklists(ip):
    listed_in = []
    for dnsbl in dnsbls:
        if ':' in ip:
            continue
        reversed_ip = reverse_ip(ip)
        if not reversed_ip:
            continue
        query = f"{reversed_ip}.{dnsbl}"
        try:
            dns.resolver.resolve(query, "A", lifetime=5)
            listed_in.append(dnsbl)
        except dns.resolver.NXDOMAIN:
            continue
        except Exception:
            continue
    return listed_in

def get_ip_info(ip):
    country, owner, comment = "Unknown", "Unknown", ""
    try:
        obj = IPWhois(ip)
        data = obj.lookup_rdap(asn_methods=["whois", "http"])
        network = data.get("network", {})
        country = network.get("country", "Unknown")
        owner = network.get("name", "Unknown")

        if country == "Unknown" or owner == "Unknown":
            comment = "Likely NAT/Carrier-Grade NAT or poor RIR registration"

    except exceptions.IPDefinedError:
        owner = "Private/Reserved"
        comment = "IP is from a reserved/private range"
    except Exception as e:
        comment = f"WHOIS lookup failed or timeout: {str(e)}"

    return country, owner, comment

def process_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        try:
            ip = socket.gethostbyname(ip)
        except Exception:
            with lock:
                results.append({
                    "IP": ip,
                    "Country": "Invalid",
                    "Owner/Org": "Could not resolve",
                    "Blacklisted In": "",
                    "Blacklist Count": 0,
                    "Comment": "Invalid IP or Domain"
                })
            return

    try:
        country, owner, comment = get_ip_info(ip)
        blacklisted = check_blacklists(ip)
    except Exception as e:
        country, owner, blacklisted, comment = "Unknown", "Unknown", [], f"Processing error: {str(e)}"

    with lock:
        results.append({
            "IP": ip,
            "Country": country,
            "Owner/Org": owner,
            "Blacklisted In": ", ".join(blacklisted),
            "Blacklist Count": len(blacklisted),
            "Comment": comment
        })

def main(input_file):
    with open(input_file, 'r') as f:
        ip_list = [line.strip() for line in f if line.strip() and not line.startswith("IP Address")]

    threads = []
    for ip in ip_list:
        t = threading.Thread(target=process_ip, args=(ip,))
        t.start()
        threads.append(t)
        time.sleep(0.1)  # Rate limiting

    for t in threads:
        t.join()

    df = pd.DataFrame(results)
    df = df.sort_values(by="Blacklist Count", ascending=False)
    df.to_excel("enhanced_blacklist_check_results.xlsx", index=False)
    print("[+] Results saved to enhanced_blacklist_check_results.xlsx")

if __name__ == "__main__":
    main("/PATH/TO/NOTORIOUSIP.TXT")
