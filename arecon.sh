#!/bin/bash

# Function to log messages
log() {
    echo "$(date +"%Y-%m-%d %T") - $1" >>script.log
}

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if amass is installed
if ! command_exists "amass"; then
    echo "Error: amass is not installed. Please install amass and try again."
    exit 1
fi

# Check if subfinder is installed
if ! command_exists "subfinder"; then
    echo "Error: subfinder is not installed. Please install subfinder and try again."
    exit 1
fi

# Check if assetfinder is installed
if ! command_exists "assetfinder"; then
    echo "Error: assetfinder is not installed. Please install assetfinder and try again."
    exit 1
fi

# Check if getsubdomain is installed
if [ ! -f "/opt/tlshelpers/getsubdomain" ]; then
    echo "Error: getsubdomain is not found in /opt/tlshelpers directory. Please check the path or install it and try again."
    exit 1
fi

# Check if gau is installed
if ! command_exists "gau"; then
    echo "Error: gau is not installed. Please install gau and try again."
    exit 1
fi

# Check if hakrawler is installed
if ! command_exists "hakrawler"; then
    echo "Error: hakrawler is not installed. Please install hakrawler and try again."
    exit 1
fi

# Check if httpx is installed
if ! command_exists "httpx"; then
    echo "Error: httpx is not installed. Please install httpx and try again."
    exit 1
fi

# Check if nuclei is installed
if ! command_exists "nuclei"; then
    echo "Error: nuclei is not installed. Please install nuclei and try again."
    exit 1
fi

# Prompt user for target domain
read -p "Enter target.com: " target_domain

# Set up error handling
set -e

# Create output directory
mkdir -p "$target_domain" && cd "$target_domain"

# Logging function
log "Starting reconnaissance on $target_domain"

echo "Starting recon on $target_domain"
echo "Running amass on Domain"
amass enum -d "$target_domain" -o "$target_domain.amass.txt" | tee raw.amass

echo "Grepping out Autonomous System Numbers"
cat raw.amass | grep "ASN:" | awk '{print $2}' | sort -u | tee "$target_domain.asn.txt"

echo "Running amass on ASN's"
amass intel --asn-file "$target_domain.asn.txt" | tee "$target_domain.asnfile.txt"

echo "Grepping out subdomains of the given target"
grep -oE '[a-zA-Z0-9.-]+\.'"$target_domain"'\.com' "$target_domain.asnfile.txt" | tee "$target_domain.finalans.txt"
grep -oE '[a-zA-Z0-9.-]+\.'"$target_domain"'\.com' raw.amass | tee amass.subs.txt

echo "Starting Subdomain Enum"
echo "Running subfinder"
mkdir subs
cd subs
subfinder -d "$target_domain" | tee "$target_domain.subfinder" && cat "$target_domain.subfinder" | assetfinder | tee sub.assetfinder.txt && cat "$target_domain.subfinder" | assetfinder -subs-only | tee subsonly.txt

cd /opt/tlshelpers
./getsubdomain "$target_domain" | tee crt.subs

cd
cd Desktop/"$target_domain"
echo "Crawling Time"
echo "Starting Get All Url gau"
gau --subs "$target_domain" | cut -d / -f 3 | sort -u | tee gau.txt

echo "Merging all subdomain output and removing duplicates"
cat ../amass.subs.txt ../"$target_domain.finalans.txt" "$target_domain.subfinder" sub.assetfinder.txt subsonly.txt | sort -u | tee final.txt

echo "Running Hakrawler"
cat final.txt | hakrawler -d3 | tee crawl.txt

echo "Finding alive subdomains"
cat final.txt | httpx | tee alive.txt

echo "Running scanner on subdomains"
echo "Until try some manual hunting"

nuclei -l alive.txt | tee raw.nuclei

log "Reconnaissance completed successfully."

# Disable error handling at the end
set +e
