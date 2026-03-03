#!/bin/bash

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 monkeytype.com"
    exit 1
fi

DOMAIN="$1"
ENUM_OUTPUT="${DOMAIN}_enum.txt"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "=================================================="
echo "DOMAINLESS IP FINDER FOR: $DOMAIN"
echo "=================================================="

# Step 1: Run amass enum
echo "[1/6] Running amass enum -d $DOMAIN -passive ..."
amass enum -d "$DOMAIN" -passive > "$ENUM_OUTPUT"

if [ ! -s "$ENUM_OUTPUT" ]; then
    echo "[-] Amass enum produced no output. Exiting."
    exit 1
fi
echo "[+] Amass enum completed. Output saved to: $ENUM_OUTPUT"
echo ""

# Step 2: Extract ASN numbers from enum output
echo "[2/6] Extracting ASN numbers from enum output..."
grep -E '\(ASN\)' "$ENUM_OUTPUT" | grep -oE '^[0-9]+' | sort -u > asn_list.txt

if [ ! -s asn_list.txt ]; then
    echo "[-] No ASN found in enum output."
    exit 1
fi

echo "[+] Found ASNs: $(cat asn_list.txt | tr '\n' ' ')"
echo "[+] Total ASNs: $(wc -l < asn_list.txt)"
echo ""

# Step 3: Extract CIDRs from enum output
echo "[3/6] Extracting CIDRs from enum output..."
grep -E '\(Netblock\)' "$ENUM_OUTPUT" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort -u > cidr_list.txt

if [ -s cidr_list.txt ]; then
    echo "[+] Found $(wc -l < cidr_list.txt) IPv4 CIDRs"
else
    echo "[!] No IPv4 CIDRs found in enum output"
fi
echo ""

# Step 4: For each ASN, run amass intel to get domains+IPs
echo "[4/6] Running amass intel on each ASN to find domains and IPs..."
> all_domains_with_ips.txt
TOTAL_ASNS=$(wc -l < asn_list.txt)
COUNT=0

for asn in $(cat asn_list.txt); do
    COUNT=$((COUNT + 1))
    echo "  [$COUNT/$TOTAL_ASNS] Processing ASN: $asn"
    
    # Run amass intel for this ASN and append to file
    amass intel -asn "$asn" -ip >> all_domains_with_ips.txt 2>/dev/null
    
    # Small delay to be nice to rate limits
    sleep 1
done

if [ ! -s all_domains_with_ips.txt ]; then
    echo "[-] No domain/IP data found from ASN queries."
    exit 1
fi
echo "[+] Total lines in all_domains_with_ips.txt: $(wc -l < all_domains_with_ips.txt)"
echo ""

# Step 5: Extract known IPs (second column) from the amass intel output
echo "[5/6] Extracting known IPs from amass intel output..."
awk '{print $2}' all_domains_with_ips.txt | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > known_ips.txt

if [ -s known_ips.txt ]; then
    echo "[+] Found $(wc -l < known_ips.txt) unique known IPv4 addresses"
else
    echo "[!] No known IPs extracted"
fi
echo ""

# Step 6: Expand CIDRs to generate all possible IPs
echo "[6/6] Expanding CIDRs to generate all possible IPs..."

# Check if prips is installed
if ! command -v prips &> /dev/null; then
    echo "[!] prips not found. Attempting to install..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y prips
    elif command -v yum &> /dev/null; then
        yum install -y prips
    else
        echo "[-] Could not install prips. Please install it manually."
        exit 1
    fi
fi

# Process each CIDR with prips
> all_possible_ips.txt
CIDR_COUNT=$(wc -l < cidr_list.txt)
CURRENT=0

if [ -s cidr_list.txt ]; then
    while read cidr; do
        CURRENT=$((CURRENT + 1))
        echo -ne "  Processing CIDR $CURRENT/$CIDR_COUNT: $cidr\r"
        prips "$cidr" >> all_possible_ips.txt 2>/dev/null
    done < cidr_list.txt
    echo ""  # New line after progress
    echo "[+] Generated $(wc -l < all_possible_ips.txt) total possible IPv4 addresses"
else
    echo "[!] No CIDRs to process"
    touch all_possible_ips.txt
fi
echo ""

# Step 7: Find domainless IPs (in all_possible_ips.txt but not in known_ips.txt)
echo "[+] Identifying domainless IPv4 candidates..."
if [ -s all_possible_ips.txt ] && [ -s known_ips.txt ]; then
    comm -23 <(sort all_possible_ips.txt) <(sort known_ips.txt) > domainless_ips.txt
    echo "[+] Found $(wc -l < domainless_ips.txt) potential domainless IPv4 addresses"
else
    echo "[!] Cannot compare - missing files"
    > domainless_ips.txt
fi
echo ""

# Step 8: Generate final report
REPORT_FILE="${DOMAIN}_report_${TIMESTAMP}.txt"

echo "==================================================" > "$REPORT_FILE"
echo "DOMAINLESS IP FINDER REPORT" >> "$REPORT_FILE"
echo "Domain: $DOMAIN" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "==================================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "SUMMARY" >> "$REPORT_FILE"
echo "-------" >> "$REPORT_FILE"
echo "ASNs Found: $(wc -l < asn_list.txt)" >> "$REPORT_FILE"
echo "CIDRs Found: $(wc -l < cidr_list.txt)" >> "$REPORT_FILE"
echo "Known IPs (from ASN queries): $(wc -l < known_ips.txt)" >> "$REPORT_FILE"
echo "Total Possible IPs (from CIDRs): $(wc -l < all_possible_ips.txt)" >> "$REPORT_FILE"
echo "Domainless IP Candidates: $(wc -l < domainless_ips.txt)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "ASN LIST" >> "$REPORT_FILE"
echo "--------" >> "$REPORT_FILE"
cat asn_list.txt >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "CIDR LIST" >> "$REPORT_FILE"
echo "---------" >> "$REPORT_FILE"
cat cidr_list.txt >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "DOMAINLESS IP CANDIDATES (First 50)" >> "$REPORT_FILE"
echo "-----------------------------------" >> "$REPORT_FILE"
if [ -s domainless_ips.txt ]; then
    head -50 domainless_ips.txt >> "$REPORT_FILE"
    if [ $(wc -l < domainless_ips.txt) -gt 50 ]; then
        echo "... and $(($(wc -l < domainless_ips.txt) - 50)) more" >> "$REPORT_FILE"
    fi
else
    echo "No domainless IPs found" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

echo "SAMPLE KNOWN IPS (First 20)" >> "$REPORT_FILE"
echo "--------------------------" >> "$REPORT_FILE"
head -20 known_ips.txt >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "==================================================" >> "$REPORT_FILE"

# Display quick summary
echo "=================================================="
echo "[✔] ANALYSIS COMPLETE!"
echo "=================================================="
echo ""
echo "📊 QUICK SUMMARY:"
echo "   - Domain: $DOMAIN"
echo "   - ASNs found: $(wc -l < asn_list.txt)"
echo "   - CIDRs found: $(wc -l < cidr_list.txt)"
echo "   - Known IPs: $(wc -l < known_ips.txt)"
echo "   - Domainless IP candidates: $(wc -l < domainless_ips.txt)"
echo ""
echo "📁 FILES GENERATED:"
echo "   - $ENUM_OUTPUT                    (Raw amass enum output)"
echo "   - asn_list.txt                     (All ASN numbers)"
echo "   - cidr_list.txt                     (All CIDRs)"
echo "   - all_domains_with_ips.txt           (All domain+IP pairs from ASN queries)"
echo "   - known_ips.txt                       (Known IPs extracted)"
echo "   - all_possible_ips.txt                  (All possible IPs from CIDRs)"
echo "   - domainless_ips.txt                      (Domainless IP candidates)"
echo "   - $REPORT_FILE  (Complete report)"
echo ""
echo "🔍 NEXT STEPS:"
echo "   1. Check domainless_ips.txt for potential targets"
echo "   2. Verify candidates with: amass intel -addr <IP>"
echo ""
echo "📝 Example verification command:"
echo "   head -5 domainless_ips.txt | while read ip; do"
echo "       echo \"Checking \$ip...\""
echo "       amass intel -addr \$ip -whois | head -3"
echo "   done"
echo "=================================================="

# Show top 10 domainless candidates if any
if [ -s domainless_ips.txt ]; then
    echo ""
    echo "🔟 TOP 10 DOMAINLESS CANDIDATES:"
    head -10 domainless_ips.txt | nl -w2 -s'. '
fi

echo ""
echo "✅ Script finished successfully!"

# mv cidr.txt asn.txt domains_with_ips.txt all_known_ips.txt all_ips.txt domainless_ips.txt "$output_folder"
