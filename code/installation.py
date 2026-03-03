#### removal of all tools including python's httpx.
#### installation of all tools.
#### installation of python library requests.
#### go bin path export in bashrc n zshrc.
#### figure out that ghost bug of subfinder.

import subprocess as sp

TOOLS = [
    {
        "name": "nmap",
        "cmd": "sudo apt install nmap -y",
        "extra": ""
    },
    {
        "name": "go",
        "cmd": "sudo apt install golang-go -y",
        "extra": r"""RC=~/."${0##*/}"rc; echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> "$RC" && . "$RC" """
    },
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




'''
