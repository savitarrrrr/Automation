#!/bin/bash
read -p "Enter target.com " target
# Logging function
log() {
	echo "$(date +"%Y-%m-%d %T") - $1" >>script.log
}

log "Starting reconnaissance on $target"

mkdir $target && cd $target

echo "Starting recon on $target"
echo "Running amass on Domain"
amass enum -d $target -o $target.amass.txt | tee raw.amass

echo "grepping out Autonomous System Numbers"
cat raw.amass | grep "ASN:" | awk '{print $2}' | sort -u | tee $target.asn.txt

echo "running amass on ASN's"
amass intel --asn-file $target.asn.txt | tee $target.asnfile.txt

echo "grepping out subdomains of the given target"
grep -oE '[a-zA-Z0-9.-]+\.$target\.com' $target.asnfile.txt | tee $target.finalans.txt
grep -oE '[a-zA-Z0-9.-]+\.$target\.com' raw.amass | tee amass.subs.txt

echo "Starting Subdomain Enum"
echo "running subfinder"
mkdir subs
cd subs
subfinder -d $target | tee $target.subfinder && cat $target.subfinder | assetfinder | tee sub.assetfinder.txt && cat $target.subfinder | assetfinder -subs-only | tee subsonly.txt

cd /opt/tlshelpers
./getsubdomain $target | tee crt.subs

cd
cd Desktop/$target
echo "Crawling Time"
echo"Starting Get All Url gau"
gau --subs $target | cut -d / -f 3 | sort -u | tee gau.txt

echo "merging all subdomain output and removing duplicates"
cat ../amass.subs.txt ../$target.finalans.txt $target.subfinder sub.assetfinder.txt subsonly.txt | sort -u | tee final.txt

echo "Running Hakrawler"
cat final.txt | hakrawler -d3 | tee crawl.txt

echo "Finding alive subdomains"
cat final.txt | httpx | tee alive.txt

echo "Running scanner on subdomains "
echo "Untill try some manual hunting"

nuclei -l alive.txt | tee raw.nuclei

log "Reconnaissance completed successfully."

