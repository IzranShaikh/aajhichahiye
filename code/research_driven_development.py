import subprocess
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import requests
import json
import os
import socket
from collections import defaultdict
from urllib.parse import urlparse
import uuid
from urllib.parse import urlparse
from typing import Optional, Dict, Any

OUTPUT_DIR = None

def validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("Domain must be a non-empty string")
    domain = domain.strip()
    # If scheme exists, extract netloc
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc
    # Remove port if present (example.com:8080 → example.com)
    domain = domain.split(":")[0]
    # Remove trailing dot (example.com.)
    domain = domain.rstrip(".")
    # Regex for valid domain
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )
    if not pattern.match(domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain.lower()

# -------------------------
# TOOL CONFIGURATION
# -------------------------
TOOLS = {
    "subfinder": {
        "cmd": lambda domain: ["subfinder", "-d", domain, "-silent"],
        "output": "subfinder.txt",
        "blocking": True
    },
    "sublist3r": {
        "cmd": lambda domain: ["sublist3r", "-d", domain, "-n", "-o", OUTPUT_DIR /"sublist3r.txt"],
        "output": "lister.txt",
        "blocking": False
    },
    # "amass": {
    #     "cmd": lambda domain: ["amass", "enum", "-passive", "-d", domain],
    #     "output": "amass.txt",
    #     "blocking": False
    # },
    "httpx": {
        "cmd": lambda _: ["httpx", "-silent", 
                          #"-p", "1-65535", 
                          "-l", OUTPUT_DIR / "subdomains.txt"],
        "output": "live.txt",
        "blocking": True
    },
    "wafw00f": {
        "cmd": lambda _: ["wafw00f", "-i", OUTPUT_DIR / "live.txt", "-f", "json", "-o", OUTPUT_DIR / "wafw00f.json"],
        "output": "wafw00f.txt",
        "blocking": True
    },
    "nmap": {
        "cmd": lambda _: ["nmap", "-iL", OUTPUT_DIR / "ns_live.txt", "--script", "http-waf-detect", "-p80,443,8080,8443", "-oX", OUTPUT_DIR / "nmap.xml"],
        "output": "nmap.txt",
        "blocking": True
    },
    "httpx2": {
        "cmd": lambda _: ["httpx", "-silent", "-nc",
                          #"-p", "1-65535",
                          "-l", OUTPUT_DIR / "scanmap.txt",
                          "-sc", "-title", "-td",
                          "-json"],
        "output": "livescanmap.json",
        "blocking": True
    },
}


WEB_TOOLS = {
    "crtsh": {
        "url": "https://crt.sh/",
        "params": lambda domain: {
            "q": domain,
            "output": "json"
        },
        "output_file": "crtsh.json"
    },

    "certspotter": {
        "url": "https://api.certspotter.com/v1/issuances",
        "params": lambda domain: {
            "domain": domain,
            "include_subdomains": "true"
        },
        "output_file": "certspotter.json"
    },
}


def resolve_subdomains(subdomains):
    mapping = defaultdict(list)
    for sub in subdomains:
        try:
            hostname = urlparse(sub).hostname
            ip = socket.gethostbyname(hostname)
            mapping[ip].append(sub)
        except Exception:
            continue
    return dict(mapping)

def execute_request(config: Dict[str, Any], timeout: int):
    method = config.get("method", "GET").upper()
    url = config["url"]
    headers = config.get("headers", {})
    params = config.get("params", {})
    data = config.get("data", None)
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json=data,
        # timeout=timeout
    )
    response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return response.text

def write_output(filename: str, data):
    if isinstance(data, (dict, list)):
        with open(OUTPUT_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        with open(OUTPUT_DIR / filename, "w", encoding="utf-8") as f:
            f.write(data)

def deduplicate_ips(mapping):
    unique_ips = set(mapping.keys())
    return list(unique_ips)

# -------------------------
# NMAP PARSING
# -------------------------
def extract_http_services_from_nmap(xml_file, output_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    results = set()
    for host in root.findall("host"):
        address = host.find("address").get("addr")
        for port in host.findall(".//port"):
            state = port.find("state").get("state")
            service = port.find("service")
            if state == "open" and service is not None:
                name = service.get("name", "").lower()
                if "http" in name:
                    portid = port.get("portid")
                    results.add(f"{address}:{portid}")
    with open(output_file, "w") as f:
        for entry in sorted(results):
            f.write(entry + "\n")
    print(f"[+] Written {len(results)} HTTP services to {output_file}")

def map_ips_with_domains_and_port(scan_file, mapping_file, output_file):
    ip_to_ports = defaultdict(list)
    results = []
    with open(scan_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            ip, port = line.split(":", 1)
            ip_to_ports[ip].append(port)

    with open(mapping_file, "r") as f:
        ip_to_domains = json.load(f)

    for ip, domains in ip_to_domains.items():
        ports = ip_to_ports.get(ip, [])
        for domain in domains:
            for port in ports:
                results.append(f"{domain}:{port}")
                
    with open(output_file, "w") as f:
        f.write("\n".join(results))
    print(f"[✓] Mapping completed. Output written to {output_file}")

def read_urls(file_path) -> list[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]
    
def remove_scheme(input_file, output_file):
    schemed_urls = read_urls(input_file)
    with open(output_file, "w") as f:
        for u in schemed_urls:
            f.write(u.split("://")[1] + "\n")

# def write_ip_outputs(enabled_map, disabled_map):
#     # Write flat IP lists
#     with open(OUTPUT_DIR / "waf_enabled_ips.txt", "w") as f:
#         for ip in sorted(enabled_map.keys()):
#             f.write(ip + "\n")
#     with open(OUTPUT_DIR / "waf_disabled_ips.txt", "w") as f:
#         for ip in sorted(disabled_map.keys()):
#             f.write(ip + "\n")
#     # Write mapping JSON
#     with open(OUTPUT_DIR / "waf_enabled_ip_map.json", "w") as f:
#         json.dump(enabled_map, f, indent=2)
#     with open(OUTPUT_DIR / "waf_disabled_ip_map.json", "w") as f:
#         json.dump(disabled_map, f, indent=2)
#     print(f"enabled IPs: {len(enabled_map)}")
#     print(f"disabled IPs: {len(disabled_map)}")

def split_waf_results(input_file):
    with open(input_file, "r") as f:
        data = json.load(f)
    waf_enabled = set()
    waf_disabled = set()
    for entry in data:
        url = entry.get("url")
        detected = entry.get("detected", False)
        if not url:
            continue
        normalized = normalize_domain(url)
        if not normalized:
            continue
        if detected:
            waf_enabled.add(normalized)
        else:
            waf_disabled.add(normalized)
    with open(OUTPUT_DIR / "waf_enabled.txt", "w") as f:
        for url in sorted(waf_enabled):
            f.write(url + "\n")
    with open(OUTPUT_DIR / "waf_disabled.txt", "w") as f:
        for url in sorted(waf_disabled):
            f.write(url + "\n")
    print(f"WAF enabled: {len(waf_enabled)}")
    print(f"WAF disabled: {len(waf_disabled)}")

# -------------------------
# COMMAND RUNNER 
# -------------------------
def run_tool(name, tool_config, domain):
    outfile = OUTPUT_DIR / tool_config["output"]
    print(f"[*] Running {name}...")
    process = subprocess.Popen(
        tool_config["cmd"](domain),
        stdout=open(outfile, "w"),
        stderr=subprocess.PIPE,
        text=True
    )
    return name, process

def run_web_recon(tools_config: Dict[str, Dict[str, Any]], domain: str, timeout: int = 15):
    for tool_name, config in tools_config.items():
        print(f"[+] Running {tool_name}")
        try:
            params = config.get("params")
            if callable(params):
                config = {**config, "params": params(domain)}
            response = execute_request(config, timeout)
            write_output(config["output_file"], response)
            print(f"[✓] {tool_name} completed")
        except Exception as e:
            print(f"[!] {tool_name} failed: {str(e)}")


# -------------------------
# DEDUP FUNCTION
# -------------------------
def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def merge_and_dedupe(files, output_file):
    unique = set()
    for file in files:
        if file.exists():
            with open(file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        normalized = normalize_domain(line)
                        if normalized:
                            unique.add(normalized)
    with open(output_file, "w") as f:
        for item in sorted(unique):
            f.write(item + "\n")

def write_text(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

# -------------------------
# PIPELINE
# -------------------------
def run_pipeline(domain):
    processes = {}

    # -------------------------
    # STAGE 0: SUBDOMAIN ENUM EXTRA
    # -------------------------
    print("[*] Running enumeration tools...")
    run_web_recon(WEB_TOOLS, domain)

    # -------------------------
    # STAGE 1: SUBDOMAIN ENUM
    # -------------------------
    for name in ["subfinder", "sublist3r"]:
        tool = TOOLS[name]
        tool_name, proc = run_tool(name, tool, domain)
        processes[tool_name] = proc
    for name in ["subfinder", "sublist3r"]:
        tool = TOOLS[name]
        if tool["blocking"]:
            print(f"[*] Waiting for {name}...")
            processes[name].wait()
            print(f"[+] {name} done")

    # -------------------------
    # STAGE 2: MERGE OUTPUTS, NORMALIZE, DEDUPE
    # -------------------------
    print("[*] Merging all the results...")
    merge_and_dedupe([OUTPUT_DIR / TOOLS["subfinder"]["output"],
            OUTPUT_DIR / "sublist3r.txt",
            OUTPUT_DIR / TOOLS["sublist3r"]["output"],
            # OUTPUT_DIR / TOOLS["amass"]["output"]
            ],OUTPUT_DIR / "subdomains.txt")
    print("[+] subdomains.txt ready")

    # -------------------------
    # STAGE 3: LIVE CHECK #1
    # -------------------------
    nextup = TOOLS["httpx"]
    name, proc = run_tool("httpx", nextup, domain)
    if nextup["blocking"]:
        proc.wait()
        print(f"[+] {name} done")

    # -------------------------
    # STAGE 4: RESOLUTION #1
    # -------------------------
    file = open(OUTPUT_DIR / 'live.txt', 'r')
    subs = []
    for li in file:
        subs.append(li.strip())
    print("[/] Resolution stage...")
    mapping = resolve_subdomains(subs)
    write_text(OUTPUT_DIR / 'mapping.json', json.dumps(mapping, indent=2))
    ips = deduplicate_ips(mapping)
    write_text(OUTPUT_DIR / 'ips.txt', "\n".join(ips))
    

    # -------------------------
    # STAGE 5: WAF DETECTION
    # -------------------------
    nextup = TOOLS["wafw00f"]
    name, proc = run_tool("wafw00f", nextup, domain)
    if nextup["blocking"]:
        proc.wait()
        print(f"[+] {name} done")
    split_waf_results(OUTPUT_DIR / "wafw00f.json")
    remove_scheme(OUTPUT_DIR / "live.txt", OUTPUT_DIR / "ns_live.txt")
    print("[+] waf detection stage finished ")

    # -------------------------
    # STAGE 6: PORT SCANNING
    # -------------------------
    print("[*] Port Scanning...")
    for name in ["nmap"]:
        tool = TOOLS[name]
        tool_name, proc = run_tool(name, tool, domain)
        processes[tool_name] = proc
        processes[name].wait()

    # -------------------------
    # STAGE 7: PORT PARSING
    # -------------------------
    print("[*] Extracting output...")
    extract_http_services_from_nmap(OUTPUT_DIR / 'nmap.xml', OUTPUT_DIR / 'scan.txt')
    print("[+] Mapping domains to port")
    map_ips_with_domains_and_port(OUTPUT_DIR / 'scan.txt', OUTPUT_DIR / 'mapping.json', OUTPUT_DIR / 'scanmap.txt')

    # -------------------------
    # STAGE 8: TECH STACK DISCOVERY AND LIVE STATUS
    # -------------------------
    print("[*] Running httpx for tech stack and live status...")
    nextup = TOOLS["httpx2"]
    name, proc = run_tool("httpx2", nextup, domain)
    if nextup["blocking"]:
        proc.wait()
        print(f"[+] {name} done. output stored in {OUTPUT_DIR / 'livescanmap.txt'}")


# -------------------------
# ENTRY
# -------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()
    try:
        domain = validate_domain(args.domain)
        scanid = str(uuid.uuid4())[:8]
        OUTPUT_DIR = Path("output") / f"{domain.split('.')[0]}_{scanid}"
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[+] Target: {domain} [ {scanid} ]")
        run_pipeline(domain)
    except Exception as e:
        print("[-] Error occured")
        print(str(e))
