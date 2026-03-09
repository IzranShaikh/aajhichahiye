from typing import Optional, Dict, Any
import subprocess
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import requests
import json
from urllib.parse import urlparse
import os
import socket
from collections import defaultdict
import uuid
from urllib.parse import urlparse

INPUT_DIR = None
OUTPUT_DIR = None

# https://github.com/JonnyHightower/neet
# http://github.com/wapiti-scanner/wapiti
# NUCLEI

TOOLS = {
    "dirsearch": {
        "cmd": lambda _: ["dirsearch", 
                               "--no-color", "-q",
                               "-l", INPUT_DIR / "scanmap.txt", 
                               "-o", OUTPUT_DIR / "dirsearch.txt"],
        # "output": "dirsearch.txt",
        "blocking": True
    },
    "nuclei": {
        "cmd": lambda _: ["nuclei",
                               "-nc", "-silent",
                               "-l", INPUT_DIR / "scanmap.txt",
                               "-t", "./nt/",
                            #    "-severity", "critical,high,medium,low",
                            #    "-c", "50",
                            #   "-rate-limit", "1500", # 1500 req/s for testing
                               "-o", OUTPUT_DIR / "nuclei.txt"],
        # "output": "nuclei.txt",
        "blocking": True
    },
    "gau": {
        "cmd": lambda domain: ["gau", domain],
        "output": "gau.txt",
        "blocking": False
    },
    "postleaks": {
        "cmd": lambda keyword: ["postleaks",
                               "-k", keyword,
                            #    "--output", OUTPUT_DIR / "postleaks.txt"
                               ],
        "output": "postleaks.txt",
        "blocking": True
    },
}

def run_tool(name, tool_config, param):
    print(f"[/] Running {name}...")
    stdout_target = None
    if tool_config.get("output"):
        outfile = OUTPUT_DIR / tool_config["output"]
        stdout_target = open(outfile, "w")
    process = subprocess.Popen(
        tool_config["cmd"](param),
        stdout=stdout_target,
        stderr=subprocess.PIPE,
        text=True
    )
    return name, process



def run_pipeline(domain):
    processes = {}

    # -------------------------
    # STAGE 0: 
    # -------------------------
    nextup = TOOLS["nuclei"]
    name, proc = run_tool("nuclei", nextup, "")
    if nextup["blocking"]:
        proc.wait()
        print(f"[+] {name} done")

    # -------------------------
    # STAGE 1: RUN MORE SCAN TOOLS (UNDER TESTING)
    # -------------------------
    for name in ["dirsearch", "gau", "postleaks"]:
        tool = TOOLS[name]
        tool_name, proc = run_tool(name, tool, "")
        processes[tool_name] = proc
    for name in ["dirsearch", "gau", "postleaks"]:
        tool = TOOLS[name]
        if tool["blocking"]:
            print(f"[*] Waiting for {name}...")
            processes[name].wait()
            print(f"[+] {name} done")


# -------------------------
# ENTRY
# -------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Domain name")
    parser.add_argument("output_dir", help="Output directory")
    args = parser.parse_args()
    try:
        INPUT_DIR = Path(args.output_dir)
        OUTPUT_DIR = INPUT_DIR / "scan"
        print(INPUT_DIR)
        print(OUTPUT_DIR)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        run_pipeline(args.domain)
    except Exception as e:
        print("[-] Error occured")
        print(str(e))

 
