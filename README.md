# WaifuScan

## Installation and Usage

### macOS

1. Required to use tshark: <br>`brew install --cask wireshark`
2. Add MongoDB repo to brew: <br>`brew tap mongodb/brew`
3. Install MongoDB with brew: <br>`brew install mongodb/brew/mongodb-community mongosh mongodb-compass`
4. Update existing conda env with required packages: <br>`conda env update --file environment.yml --prune`

Usage:
- Start the MongoDB (required for sync): <br>`./start_mongo.sh`
- Start to sniff Wi-Fi network interface on macOS<br>`python3 waifu_scan.py -N en0`
- Crawl every folder on the filesystem starting in root folder:<br>`python3 waifu_scan.py -L "/"`

## Features

### Network Sniffing
- Live Sniffing for SSL/TLS certificates for provided network interface
- Analyse pcap(ng) files to collect certificates
- certificates are detected and collected in realtime (50ms timeout)

### Filesystem Crawling
- Filesystem-Crawling for certificates, private keys and public keys:
- detected certificates: .pem .crt .ca-bundle .p7b .p7s .der .cer .pfx .p12
- during execution: logging what kind of data was found including execution runtime
- crawling ~720 GB takes about 180 seconds

### Sync
- certificates are saved to database or local filesystem:
- used MongoDB as database to store certificates and keys
- SHA-256 hash of certificate data prevents duplicates in database

### Logging
- all certificates are tracked with inbound and outbound connections
- IP:Port of source and destination address are logged to stdout during execution
