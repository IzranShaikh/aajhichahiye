#!/bin/bash

amass intel -org "$1" -whois > cidr.txt

if [ ! -s cidr.txt ]; then
    echo "[-] No CIDR data found. Exiting."
    exit 1
fi

echo "[+] Extracting ASN numbers..."
grep -oE 'ASN:[[:space:]]*[0-9]+' cidr.txt | awk -F':' '{print $2}' | tr -d ' ' | sort -u > asn.txt

if [ ! -s asn.txt ]; then
    echo "[-] No ASN found. Exiting."
    exit 1
fi

echo "[+] Running amass intel on extracted ASNs..."
> godaddy_domains_with_ips.txt

for asn in $(cat asn.txt); do
    echo "[+] Querying ASN: $asn"
    amass intel -asn $asn -ip >> godaddy_domains_with_ips.txt
done

echo "[+] Extracting known IPs..."
awk '{print $2}' godaddy_domains_with_ips.txt | sort -u > all_known_ips.txt

echo "[+] Expanding CIDRs..."
> all_godaddy_ips.txt
for cidr in $(cat cidr.txt | awk '{print $1}'); do
    prips $cidr >> all_godaddy_ips.txt
done

echo "[+] Finding domainless IPs..."
comm -23 <(sort all_godaddy_ips.txt) <(sort all_known_ips.txt) > candidate_domainless_ips.txt

echo "=================================="
echo "[✔] Done!"
echo "[+] Files generated:"
echo " - cidr.txt"
echo " - asn.txt"
echo " - godaddy_domains_with_ips.txt"
echo " - all_known_ips.txt"
echo " - all_godaddy_ips.txt"
echo " - candidate_domainless_ips.txt"
echo "=================================="