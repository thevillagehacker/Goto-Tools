#!/bin/bash
set -euo pipefail

# Set vars
id="$1"
ppath="$(pwd)"
scope_path="$ppath/scope/$id"
timestamp="$(date +%s)"
scan_path="$ppath/scans/$id-$timestamp"

# Usage and disclaimer
if [ "${1:-}" == "-h" ] || [ -z "${1:-}" ]; then
    echo "Usage: ./scan.sh <id>"
    echo "This script performs a scan for a given <id>. Ensure the following structure is in place:"
    echo "├── scan.sh"
    echo "├── scans"
    echo "└── scope"
    echo "    └── <id>"
    echo "        └── roots.txt"
    echo "Example:"
    echo "chmod +x scan.sh"
    echo "mkdir -p scope/example/"
    echo "touch scope/example/roots.txt"
    echo "./scan.sh example"
    exit 0
fi

# Exit if scope_path doesn't exist or roots.txt is missing/empty
if [ ! -d "$scope_path" ]; then
    echo "Path doesn't exist: $scope_path"
    exit 1
fi

if [ ! -s "$scope_path/roots.txt" ]; then
    echo "roots.txt not found or empty in $scope_path"
    exit 1
fi

mkdir -p "$scan_path"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"
echo "Scan output directory: $scan_path"

### PERFORM SCAN ###
echo "Starting scan against roots:"
cat "$scan_path/roots.txt"

# DNS Enumeration - Find Subdomains (run in parallel for speed)
(
    haktrails subdomains < "$scan_path/roots.txt" | anew "$scan_path/subs.txt"
) &
(
    subfinder -dL "$scan_path/roots.txt" | anew "$scan_path/subs.txt"
) &
wait

# Uncomment and update paths if you want to use shuffledns
# shuffledns -dL "$scan_path/roots.txt" -w "$ppath/lists/dns.txt" -r "$ppath/lists/resolvers.txt" -mode bruteforce | anew "$scan_path/subs.txt"

# DNS Resolution - Resolve Discovered Subdomains
puredns resolve "$scan_path/subs.txt" -r "$ppath/lists/resolvers.txt" -w "$scan_path/resolved.txt"

# DNSx for IPs and JSON results
dnsx -l "$scan_path/resolved.txt" -json -o "$scan_path/dns.json"
jq -r '.. | objects | to_entries[] | select(.value | tostring | test("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) | .value' "$scan_path/dns.json" > "$scan_path/ips.txt"

# Port Scanning & HTTP Server Discovery
if [ -s "$scan_path/ips.txt" ]; then
    nmap -iL "$scan_path/ips.txt" --top-ports 3000 -oN "$scan_path/nmap.xml" -v
fi

# HTTP Probing
if [ -s "$scan_path/nmap.xml" ]; then
    # Assuming dnsx can accept nmap xml and output hosts
    dnsx -l "$scan_path/dns.json" --hosts | httpx -json -o "$scan_path/http.json"
    jq -r '.url' "$scan_path/http.json" | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u > "$scan_path/http.txt"
else
    echo "No nmap results found, skipping HTTP probing."
fi

# Crawling
if [ -s "$scan_path/http.txt" ]; then
    gospider -S "$scan_path/http.txt" --json | grep '{}' | jq -r '.output?' | tee "$scan_path/crawl.txt"
fi

# Calculate time diff
end_time=$(date +%s)
seconds=$((end_time - timestamp))

if [ "$seconds" -gt 59 ]; then
    minutes=$((seconds / 60))
    time="$minutes minutes"
else
    time="$seconds seconds"
fi

echo "Scan $id took $time"
# echo "Scan $id took $time" | notify