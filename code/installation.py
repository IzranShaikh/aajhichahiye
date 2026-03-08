#### self installing script.
#### ghost bug fixed ig.

import subprocess as sp
import os

def set_startup_command(command):
    home = os.environ["HOME"]
    config_files = [
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".zshrc")
    ]
    marker_start = "# ENV_SETTINGS_START"
    marker_end = "# ENV_SETTINGS_END"
    for config in config_files:
        if os.path.exists(config):
            with open(config, "r") as f:
                lines = f.readlines()
            new_lines = []
            inside_block = False
            for line in lines:
                if marker_start in line:
                    inside_block = True
                    continue
                if marker_end in line:
                    inside_block = False
                    continue
                if not inside_block:
                    new_lines.append(line)
            new_lines.append("\n" + marker_start + "\n")
            new_lines.append(command + "\n")
            new_lines.append(marker_end + "\n")
            with open(config, "w") as f:
                f.writelines(new_lines)
    print(f"\n{str(command)} set successfully")

TOOLS = [
    {
        "name": "nmap",
        "cmd": "sudo apt install nmap -y",
        "extra": ""
    },
    {
        "name": "pipx",
        "cmd": "sudo apt install pipx -y",
        "extra": "pipx ensurepath"
    },
    {
        "name": "postleaks",
        "cmd": "pipx install postleaks",
        "extra": ""
    },
    # {
    #     "name": "go",
    #     "cmd": "sudo apt install golang-go -y",
    #     "extra": r"""RC=~/."${0##*/}"rc; echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> "$RC" && . "$RC" """
    # },
    {
        "name": "dirsearch",
        "cmd": "sudo apt install dirsearch -y",
        "extra": ""
    },
    {
        "name": "wafw00f",
        "cmd": "sudo apt install wafw00f -y",
        "extra": ""
    },
    {
        "name": "subfinder",
        "cmd": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "extra": ""
    },
    {
        "name": "httpx",
        "cmd": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "extra": ""
    },
    {
        "name": "nuclei",
        "cmd": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "extra": ""
    },
    {
        "name": "amass",
        "cmd": "go install github.com/owasp-amass/amass/v4/...@master",
        "extra": ""
    },
    {
        "name": "sublist3r",
        "cmd": "sudo apt install sublist3r -y",
        "extra": ""
    },
    {
        "name": "requests",
        "cmd": "pip install requests",
        "extra": "sudo apt install python3-requests -y"
    }
]


def installer(config):
    print(f'Installing {config["name"]}...')
    sp.call(config["cmd"], shell=True)
    if config["extra"] != "":
        print(f'\nRunning additional setup commands {config["extra"]}')
        sp.call(config["extra"], shell=True)
    print(f'[+] {config["name"]} installation complete!')
    print("\n\n-----------------------------------\n\n")

for t in TOOLS:
    installer(t)

set_startup_command('export PATH=$PATH:$(go env GOPATH)/bin')
set_startup_command('export PATH=$PATH:~/.local/bin')
set_startup_command('export PATH=$PATH:$(pwd)')

print("\n\n[+] All tools installed! Please restart your terminal to apply changes.")
