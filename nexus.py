#!/usr/bin/env python3
"""NEXUS OSINT 3.0 - Public Information & Network Analysis Tool.
Standard library only. Use only on systems/information you are authorized to analyze.
"""
import concurrent.futures
import datetime
import ipaddress
import platform
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

VERSION = "3.0"
TIMEOUT = 8
REPORT = []


def log(message=""):
    print(message)
    REPORT.append(str(message))


def line(char="=", length=70):
    log(char * length)


def header():
    log()
    line()
    log("                     NEXUS OSINT")
    log("              Public Information &")
    log("               Network Analysis Tool")
    log()
    log(f"                       Version {VERSION}")
    line()
    log()


def section(number, title):
    log()
    line("-", 70)
    log(f"[TASK {number:02d}] {title}")
    line("-", 70)


def ask(prompt):
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        log("\n[!] Interrupted.")
        return ""


def normalize_domain(value):
    value = value.strip()
    if "://" in value:
        value = urllib.parse.urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0]
    return value.lower().strip(".")


def http_request(url, method="GET"):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"NEXUS-OSINT/{VERSION}", "Accept": "*/*"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return {
                "status": response.status,
                "reason": response.reason,
                "headers": dict(response.headers),
                "final_url": response.geturl(),
                "body": response.read(4096),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "reason": str(exc.reason),
            "headers": dict(exc.headers),
            "final_url": exc.geturl(),
            "body": exc.read(4096),
            "error": f"HTTP {exc.code}: {exc.reason}",
        }
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return {"status": None, "reason": "", "headers": {}, "final_url": url,
                "body": b"", "error": str(exc)}


def resolve_dns(domain):
    domain = normalize_domain(domain)
    if not domain:
        log("[!] Invalid domain.")
        return
    log(f"[*] Domain: {domain}")
    try:
        infos = socket.getaddrinfo(domain, None)
        ipv4 = sorted({x[4][0] for x in infos if ":" not in x[4][0]})
        ipv6 = sorted({x[4][0] for x in infos if ":" in x[4][0]})
        log(f"[+] IPv4: {', '.join(ipv4) if ipv4 else 'None'}")
        log(f"[+] IPv6: {', '.join(ipv6) if ipv6 else 'None'}")
    except socket.gaierror as exc:
        log(f"[!] DNS resolution failed: {exc}")


def analyze_http(domain):
    domain = normalize_domain(domain)
    if not domain:
        log("[!] Invalid domain.")
        return
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        log(f"[*] Requesting {url}")
        result = http_request(url)
        if result["status"] is None:
            log(f"[!] Connection failed: {result['error']}")
            continue
        log(f"[+] Status: {result['status']} {result['reason']}")
        log(f"[+] Final URL: {result['final_url']}")
        for name, value in result["headers"].items():
            if name.lower() in {
                "server", "content-type", "content-length", "location",
                "strict-transport-security", "x-powered-by",
                "x-frame-options", "content-security-policy",
            }:
                log(f"    {name}: {value}")
        if scheme == "https":
            break


def inspect_tls(domain):
    domain = normalize_domain(domain)
    if not domain:
        log("[!] Invalid domain.")
        return
    log(f"[*] TLS inspection: {domain}:443")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                log(f"[+] TLS version: {tls.version()}")
                cipher = tls.cipher()
                log(f"[+] Cipher: {cipher[0] if cipher else 'Unknown'}")
                subject = cert.get("subject", ())
                issuer = cert.get("issuer", ())
                def flatten(value):
                    return ", ".join(f"{k}={v}" for group in value for k, v in group)
                log(f"[+] Subject: {flatten(subject) or 'Unknown'}")
                log(f"[+] Issuer: {flatten(issuer) or 'Unknown'}")
                log(f"[+] Expires: {cert.get('notAfter', 'Unknown')}")
    except Exception as exc:
        log(f"[!] TLS inspection failed: {exc}")


def check_robots(domain):
    domain = normalize_domain(domain)
    if not domain:
        log("[!] Invalid domain.")
        return
    url = f"https://{domain}/robots.txt"
    log(f"[*] Checking {url}")
    result = http_request(url)
    if result["status"] is None:
        log(f"[!] Request failed: {result['error']}")
        return
    log(f"[+] HTTP status: {result['status']}")
    if result["status"] == 200:
        text = result["body"].decode("utf-8", errors="replace")
        lines = [x for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]
        for item in lines[:40]:
            log(f"    {item}")


def get_public_ip():
    for url in ("https://api.ipify.org", "https://icanhazip.com"):
        result = http_request(url)
        if result["status"] == 200:
            ip = result["body"].decode().strip()
            try:
                ipaddress.ip_address(ip)
                log(f"[+] Public IP: {ip}")
                return ip
            except ValueError:
                pass
    log("[!] Unable to determine public IP.")
    return None


def local_device_info():
    section(1, "LOCAL DEVICE INFORMATION")
    log(f"[+] OS: {platform.system()} {platform.release()}")
    log(f"[+] Platform: {platform.platform()}")
    log(f"[+] Architecture: {platform.machine()}")
    log(f"[+] Hostname: {socket.gethostname()}")
    log(f"[+] Python: {platform.python_version()}")


def local_network_info():
    section(2, "LOCAL NETWORK INFORMATION")
    try:
        addresses = socket.getaddrinfo(socket.gethostname(), None)
        ips = sorted({x[4][0] for x in addresses if x[4][0] not in ("127.0.0.1", "::1")})
        if ips:
            for ip in ips:
                log(f"[+] Local address: {ip}")
        else:
            log("[!] No non-loopback address detected.")
    except socket.gaierror as exc:
        log(f"[!] Network information unavailable: {exc}")
    get_public_ip()


def analyze_ip(value):
    section(3, "IP ADDRESS ANALYSIS")
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        log("[!] Invalid IP address.")
        return
    log(f"[+] Address: {ip}")
    log(f"[+] Version: IPv{ip.version}")
    log(f"[+] Private: {'Yes' if ip.is_private else 'No'}")
    log(f"[+] Global: {'Yes' if ip.is_global else 'No'}")
    log(f"[+] Loopback: {'Yes' if ip.is_loopback else 'No'}")
    log(f"[+] Multicast: {'Yes' if ip.is_multicast else 'No'}")
    log(f"[+] Reserved: {'Yes' if ip.is_reserved else 'No'}")
    try:
        hostname, aliases, _ = socket.gethostbyaddr(str(ip))
        log(f"[+] Reverse DNS: {hostname}")
        if aliases:
            log(f"[+] Aliases: {', '.join(aliases)}")
    except (socket.herror, socket.gaierror):
        log("[+] Reverse DNS: unavailable")


def tcp_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def common_ports(domain):
    section(5, "LIMITED TCP CONNECTIVITY CHECK")
    domain = normalize_domain(domain)
    if not domain:
        log("[!] Invalid domain.")
        return
    ports = (22, 25, 53, 80, 110, 143, 443, 587, 993, 995)
    log("[*] Small set of common TCP ports only.")
    log("[*] Connectivity check, not a vulnerability scan.")
    for port in ports:
        state = "OPEN/REACHABLE" if tcp_check(domain, port) else "closed/unreachable"
        log(f"    {port:>5}/tcp  {state}")


PLATFORMS = {
    "Instagram": "https://www.instagram.com/{}/",
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}/about/",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
}


def check_profile(name, username):
    safe = urllib.parse.quote(username, safe="@._-")
    url = PLATFORMS[name].format(safe)
    result = http_request(url)
    status = result["status"]
    if status == 404:
        state = "NOT FOUND"
    elif status is not None and 200 <= status < 400:
        state = "RESPONDED"
    elif status is not None:
        state = f"HTTP {status}"
    else:
        state = "ERROR"
    return name, state, result["final_url"]


def profile_search(username):
    section(4, "PUBLIC PROFILE AVAILABILITY CHECK")
    username = username.lstrip("@").strip()
    if not username:
        log("[!] Empty username.")
        return
    log(f"[*] Username: {username}")
    log("[*] Public profile URLs only.")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [pool.submit(check_profile, name, username) for name in PLATFORMS]
        for job in concurrent.futures.as_completed(jobs):
            try:
                name, state, url = job.result()
                log(f"[+] {name:<10} {state:<18} {url}")
            except Exception as exc:
                log(f"[!] Profile check failed: {exc}")


def domain_report(domain):
    REPORT.clear()
    header()
    log(f"Target: {normalize_domain(domain)}")
    log(f"Timestamp: {datetime.datetime.now().astimezone().isoformat()}")
    section(1, "DNS RESOLUTION")
    resolve_dns(domain)
    section(2, "HTTP / HTTPS ANALYSIS")
    analyze_http(domain)
    section(3, "TLS CERTIFICATE")
    inspect_tls(domain)
    section(4, "ROBOTS.TXT")
    check_robots(domain)
    common_ports(domain)


def save_report():
    if not REPORT:
        log("[!] No report data to save.")
        return
    filename = ask("Report filename [nexus_report.txt]: ") or "nexus_report.txt"
    if not filename.endswith(".txt"):
        filename += ".txt"
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write("\n".join(REPORT) + "\n")
        log(f"[+] Report saved: {filename}")
    except OSError as exc:
        log(f"[!] Could not save report: {exc}")


def show_about():
    header()
    log("NEXUS OSINT 3.0")
    log("Public Information & Network Analysis Tool")
    log("Python standard library only.")
    log()
    log("Public DNS, HTTP/HTTPS, TLS, local network, IP and profile checks.")
    log("No private-account access, authentication bypass or remote control.")
    log("Use responsibly and only on systems/information you are authorized to analyze.")


def menu():
    while True:
        header()
        log("[1] Local device information")
        log("[2] Local network information")
        log("[3] Analyze an IP address")
        log("[4] Analyze a domain")
        log("[5] Check a public username")
        log("[6] Save current report")
        log("[7] About / scope")
        log("[0] Exit")
        log()
        choice = ask("NEXUS > ")
        if choice == "1":
            local_device_info()
        elif choice == "2":
            local_network_info()
        elif choice == "3":
            analyze_ip(ask("IP address > "))
        elif choice == "4":
            domain = ask("Domain > ")
            if domain:
                domain_report(domain)
        elif choice == "5":
            profile_search(ask("Username > "))
        elif choice == "6":
            save_report()
        elif choice == "7":
            show_about()
        elif choice == "0":
            log("\n[+] NEXUS OSINT terminated.")
            return
        else:
            log("[!] Invalid option.")
        log()
        if choice != "0":
            ask("Press Enter to continue...")


def main():
    try:
        menu()
    except KeyboardInterrupt:
        log("\n[!] NEXUS OSINT interrupted by user.")
    except Exception as exc:
        log(f"\n[!] Unexpected error: {exc}")


if __name__ == "__main__":
    main()
