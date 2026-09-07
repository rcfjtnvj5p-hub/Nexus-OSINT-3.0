import urllib.request
import urllib.error
import socket
import ssl
import platform
import ipaddress
import concurrent.futures
import datetime
import re
import json
import sys
import time


# ============================================================
# NEXUS OSINT 3.0
# ============================================================
#
# 100 % Python Standard Library
#
# Aucune installation nécessaire.
#
# Modules :
#   - Profils publics
#   - DNS IPv4 / IPv6
#   - HTTP / HTTPS
#   - TLS / certificat
#   - Headers HTTP
#   - robots.txt
#   - IP publique
#   - Analyse IP
#   - Informations machine locale
#   - Informations réseau local
#   - Scan TCP limité sur une cible choisie
#   - Analyse parallèle
#   - Rapport TXT
#
# Le programme ne tente pas d'obtenir :
#   - Apple ID
#   - position privée
#   - appareil distant
#   - Wi-Fi/Bluetooth distant
#   - données privées de comptes
#
# ============================================================


VERSION = "3.0"

TIMEOUT = 5

USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36 "
    "NexusOSINT/3.0"
)

REPORT = []


# ============================================================
# UTILITAIRES
# ============================================================

def now():
    return datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def log(message):
    print(message)
    REPORT.append(message)


def line(char="=", length=70):
    print(char * length)


def section(number, title):
    print()
    line("-", 70)
    print(f"[TASK {number:02d}] {title}")
    line("-", 70)


def progress(text, duration=0.5):

    steps = 20

    for i in range(steps + 1):

        percent = int((i / steps) * 100)

        filled = int(i / 2)

        bar = (
            "#" * filled +
            "-" * (10 - filled)
        )

        sys.stdout.write(
            f"\r[{bar}] {percent:3d}% {text}"
        )

        sys.stdout.flush()

        time.sleep(
            duration / steps
        )

    print()


# ============================================================
# HTTP
# ============================================================

def create_request(url):

    return urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*"
        }
    )


def http_request(url):

    request = create_request(url)

    return urllib.request.urlopen(
        request,
        timeout=TIMEOUT
    )


# ============================================================
# TASK 01
# PROFILS PUBLICS
# ============================================================

def check_profile(platform_name, url):

    try:

        response = http_request(url)

        status = response.status

        response.close()

        if status == 200:
            result = "ACCESSIBLE"

        else:
            result = f"HTTP {status}"

        return platform_name, result

    except urllib.error.HTTPError as error:

        if error.code == 404:
            return platform_name, "NOT FOUND"

        if error.code == 403:
            return platform_name, "ACCESS DENIED"

        return platform_name, f"HTTP {error.code}"

    except urllib.error.URLError:

        return platform_name, "NETWORK ERROR"

    except Exception as error:

        return platform_name, f"ERROR: {error}"


def public_profiles(username):

    section(1, "PUBLIC PROFILE CHECK")

    username = username.strip().lstrip("@")

    profiles = {

        "Instagram":
            f"https://www.instagram.com/{username}/",

        "GitHub":
            f"https://github.com/{username}",

        "Reddit":
            f"https://www.reddit.com/user/{username}/",

        "TikTok":
            f"https://www.tiktok.com/@{username}",

        "YouTube":
            f"https://www.youtube.com/@{username}"
    }

    print(
        "[*] Running checks in parallel..."
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=5
    ) as executor:

        futures = [
            executor.submit(
                check_profile,
                name,
                url
            )
            for name, url in profiles.items()
        ]

        for future in concurrent.futures.as_completed(
            futures
        ):

            name, result = future.result()

            print(
                f"[{name:<10}] {result}"
            )

            REPORT.append(
                f"{name}: {result}"
            )


# ============================================================
# TASK 02
# DNS
# ============================================================

def dns_analysis(domain):

    section(2, "DNS ANALYSIS")

    domain = domain.strip()

    if domain.startswith("https://"):
        domain = domain[8:]

    if domain.startswith("http://"):
        domain = domain[7:]

    domain = domain.split("/")[0]

    print("[*] Domain:", domain)
    print()

    try:

        results = socket.getaddrinfo(
            domain,
            None
        )

        ipv4 = set()
        ipv6 = set()

        for result in results:

            address = result[4][0]

            try:

                ip = ipaddress.ip_address(
                    address
                )

                if ip.version == 4:
                    ipv4.add(address)

                else:
                    ipv6.add(address)

            except ValueError:
                pass

        print("[+] IPv4:")

        if ipv4:
            for ip in sorted(ipv4):
                print("    ->", ip)
        else:
            print("    None")

        print()

        print("[+] IPv6:")

        if ipv6:
            for ip in sorted(ipv6):
                print("    ->", ip)
        else:
            print("    None")

        REPORT.append(
            f"DNS {domain}: "
            f"IPv4={sorted(ipv4)} "
            f"IPv6={sorted(ipv6)}"
        )

    except socket.gaierror as error:

        print(
            "[!] DNS error:",
            error
        )


# ============================================================
# TASK 03
# HTTP HEADERS
# ============================================================

def http_analysis(url):

    section(3, "HTTP / HTTPS ANALYSIS")

    url = url.strip()

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    print("[*] URL:", url)
    print()

    try:

        response = http_request(url)

        print(
            "[+] Status:",
            response.status
        )

        print(
            "[+] Final URL:",
            response.geturl()
        )

        print()

        interesting_headers = [
            "Server",
            "Content-Type",
            "Content-Length",
            "Date",
            "Location",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for header in interesting_headers:

            value = response.headers.get(
                header
            )

            if value:

                print(
                    f"{header}: {value}"
                )

                REPORT.append(
                    f"{header}: {value}"
                )

        response.close()

    except urllib.error.HTTPError as error:

        print(
            "[!] HTTP error:",
            error.code
        )

    except urllib.error.URLError as error:

        print(
            "[!] Connection error:",
            error.reason
        )

    except Exception as error:

        print(
            "[!] Error:",
            error
        )


# ============================================================
# TASK 04
# TLS
# ============================================================

def tls_analysis(hostname):

    section(4, "TLS / CERTIFICATE ANALYSIS")

    hostname = hostname.strip()

    hostname = (
        hostname
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    print("[*] Host:", hostname)
    print()

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (hostname, 443),
            timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                print(
                    "[+] TLS version:",
                    secure_socket.version()
                )

                print(
                    "[+] Cipher:",
                    secure_socket.cipher()[0]
                )

                certificate = (
                    secure_socket.getpeercert()
                )

                if certificate:

                    subject = certificate.get(
                        "subject",
                        []
                    )

                    issuer = certificate.get(
                        "issuer",
                        []
                    )

                    not_before = certificate.get(
                        "notBefore",
                        "Unknown"
                    )

                    not_after = certificate.get(
                        "notAfter",
                        "Unknown"
                    )

                    print(
                        "[+] Certificate subject:",
                        subject
                    )

                    print(
                        "[+] Certificate issuer:",
                        issuer
                    )

                    print(
                        "[+] Valid from:",
                        not_before
                    )

                    print(
                        "[+] Valid until:",
                        not_after
                    )

                    REPORT.append(
                        f"TLS {hostname}: "
                        f"{secure_socket.version()} "
                        f"{secure_socket.cipher()[0]}"
                    )

    except Exception as error:

        print(
            "[!] TLS error:",
            error
        )


# ============================================================
# TASK 05
# ROBOTS.TXT
# ============================================================

def robots_analysis(domain):

    section(5, "ROBOTS.TXT")

    domain = domain.strip()

    if domain.startswith(
        ("http://", "https://")
    ):
        domain = domain.split("://", 1)[1]

    domain = domain.split("/")[0]

    url = (
        "https://" +
        domain +
        "/robots.txt"
    )

    print("[*] URL:", url)
    print()

    try:

        response = http_request(url)

        content = response.read(
            20000
        ).decode(
            "utf-8",
            errors="replace"
        )

        response.close()

        if content:

            print(
                "[+] robots.txt retrieved"
            )

            print()

            lines = content.splitlines()

            displayed = 0

            for item in lines:

                if (
                    item.strip() and
                    not item.startswith("#")
                ):

                    print(
                        "   ",
                        item
                    )

                    displayed += 1

                    if displayed >= 30:
                        break

        else:

            print(
                "[-] Empty robots.txt"
            )

    except Exception as error:

        print(
            "[!] robots.txt unavailable:",
            error
        )


# ============================================================
# TASK 06
# IP PUBLIQUE
# ============================================================

def public_ip():

    section(6, "PUBLIC IP")

    services = [
        "https://api.ipify.org",
        "https://icanhazip.com"
    ]

    for service in services:

        try:

            response = http_request(
                service
            )

            address = response.read().decode(
                "utf-8",
                errors="ignore"
            ).strip()

            response.close()

            if address:

                print(
                    "[+] Public IP:",
                    address
                )

                try:

                    ip = ipaddress.ip_address(
                        address
                    )

                    print(
                        "[+] Version:",
                        ip.version
                    )

                    print(
                        "[+] Global:",
                        ip.is_global
                    )

                    REPORT.append(
                        f"Public IP: {address}"
                    )

                except ValueError:
                    pass

                return

        except Exception:
            continue

    print(
        "[!] Public IP unavailable."
    )


# ============================================================
# TASK 07
# LOCAL DEVICE
# ============================================================

def local_device():

    section(7, "LOCAL DEVICE")

    data = {

        "System":
            platform.system(),

        "Release":
            platform.release(),

        "Version":
            platform.version(),

        "Machine":
            platform.machine(),

        "Processor":
            platform.processor(),

        "Python":
            platform.python_version(),

        "Hostname":
            socket.gethostname()
    }

    for key, value in data.items():

        print(
            f"[+] {key:<12}: {value}"
        )

        REPORT.append(
            f"{key}: {value}"
        )


# ============================================================
# TASK 08
# LOCAL NETWORK
# ============================================================

def local_network():

    section(8, "LOCAL NETWORK")

    hostname = socket.gethostname()

    print(
        "[*] Hostname:",
        hostname
    )

    try:

        results = socket.getaddrinfo(
            hostname,
            None
        )

        addresses = sorted(
            set(
                result[4][0]
                for result in results
            )
        )

        for address in addresses:

            try:

                ip = ipaddress.ip_address(
                    address
                )

                print(
                    f"[+] {address:<39} "
                    f"IPv{ip.version}"
                )

            except ValueError:
                pass

    except Exception as error:

        print(
            "[!] Network error:",
            error
        )


# ============================================================
# TASK 09
# IP ANALYSIS
# ============================================================

def ip_analysis():

    section(9, "IP ANALYSIS")

    value = input(
        "Enter an IP address: "
    ).strip()

    try:

        ip = ipaddress.ip_address(
            value
        )

        print(
            "[+] Address:",
            ip
        )

        print(
            "[+] Version:",
            ip.version
        )

        print(
            "[+] Private:",
            ip.is_private
        )

        print(
            "[+] Global:",
            ip.is_global
        )

        print(
            "[+] Loopback:",
            ip.is_loopback
        )

        print(
            "[+] Multicast:",
            ip.is_multicast
        )

        print(
            "[+] Reserved:",
            ip.is_reserved
        )

        REPORT.append(
            f"IP analysis: {ip}"
        )

    except ValueError:

        print(
            "[!] Invalid IP address."
        )


# ============================================================
# TASK 10
# LIMITED TCP CHECK
# ============================================================

def tcp_check():

    section(10, "TCP CONNECTIVITY CHECK")

    host = input(
        "Host to check: "
    ).strip()

    if not host:
        return

    ports = [
        80,
        443,
        22,
        21,
        25,
        53,
        8080,
        8443
    ]

    print()
    print(
        "[*] Checking a small set of common ports..."
    )

    for port in ports:

        try:

            with socket.create_connection(
                (host, port),
                timeout=1
            ):

                print(
                    f"[+] {port:<5} OPEN / reachable"
                )

        except (
            socket.timeout,
            ConnectionRefusedError,
            OSError
        ):

            print(
                f"[-] {port:<5} closed / unavailable"
            )


# ============================================================
# FULL ANALYSIS
# ============================================================

def full_analysis(username, domain):

    section(
        11,
        "FULL NEXUS ANALYSIS"
    )

    progress(
        "Initializing modules...",
        0.5
    )

    public_profiles(username)

    progress(
        "DNS analysis...",
        0.5
    )

    dns_analysis(domain)

    progress(
        "HTTP analysis...",
        0.5
    )

    http_analysis(
        "https://" + domain
    )

    progress(
        "TLS analysis...",
        0.5
    )

    tls_analysis(domain)

    progress(
        "robots.txt analysis...",
        0.5
    )

    robots_analysis(domain)

    progress(
        "Local environment...",
        0.5
    )

    local_device()

    local_network()

    public_ip()

    print()
    line()
    print(
        "             FULL ANALYSIS COMPLETE"
    )
    line()


# ============================================================
# RAPPORT
# ============================================================

def save_report():

    filename = (
        "nexus_report_"
        + datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        + ".txt"
    )

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "NEXUS OSINT REPORT\n"
            )

            file.write(
                "=" * 70 +
                "\n"
            )

            file.write(
                "Generated: "
                + now() +
                "\n\n"
            )

            for entry in REPORT:

                file.write(
                    str(entry) +
                    "\n"
                )

        print()
        print(
            "[+] Report saved:",
            filename
        )

    except Exception as error:

        print(
            "[!] Could not save report:",
            error
        )


# ============================================================
# MENU
# ============================================================

def menu(username, domain):

    while True:

        print()
        line()
        print(
            "                    NEXUS MENU"
        )
        line()

        print(
            "1  - Public profile check"
        )

        print(
            "2  - DNS analysis"
        )

        print(
            "3  - HTTP / HTTPS analysis"
        )

        print(
            "4  - TLS / certificate"
        )

        print(
            "5  - robots.txt"
        )

        print(
            "6  - Public IP"
        )

        print(
            "7  - Local device"
        )

        print(
            "8  - Local network"
        )

        print(
            "9  - IP analysis"
        )

        print(
            "10 - TCP connectivity check"
        )

        print(
            "11 - FULL ANALYSIS"
        )

        print(
            "12 - Save report"
        )

        print(
            "0  - Exit"
        )

        print()

        choice = input(
            "Nexus > "
        ).strip()

        if choice == "1":

            public_profiles(username)

        elif choice == "2":

            dns_analysis(domain)

        elif choice == "3":

            http_analysis(
                "https://" + domain
            )

        elif choice == "4":

            tls_analysis(domain)

        elif choice == "5":

            robots_analysis(domain)

        elif choice == "6":

            public_ip()

        elif choice == "7":

            local_device()

        elif choice == "8":

            local_network()

        elif choice == "9":

            ip_analysis()

        elif choice == "10":

            tcp_check()

        elif choice == "11":

            full_analysis(
                username,
                domain
            )

        elif choice == "12":

            save_report()

        elif choice == "0":

            print()
            print(
                "[*] Nexus shutting down..."
            )

            break

        else:

            print(
                "[!] Unknown command."
            )


# ============================================================
# MAIN
# ============================================================

def main():

    header()

    print(
        "NEXUS OSINT 3.0"
    )

    print(
        "Standard Library Edition"
    )

    print()
    print(
        "No external packages required."
    )

    print()

    username = input(
        "Target username: "
    ).strip()

    username = username.lstrip("@")

    if not username:

        print(
            "[!] Username required."
        )

        return

    print()

    domain = input(
        "Target domain (example.com): "
    ).strip()

    if not domain:

        print(
            "[!] Domain required."
        )

        return

    domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    print()
    line()

    print(
        "TARGET USERNAME :",
        username
    )

    print(
        "TARGET DOMAIN   :",
        domain
    )

    print(
        "START TIME      :",
        now()
    )

    line()

    menu(
        username,
        domain
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
