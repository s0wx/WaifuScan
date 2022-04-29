# WaifuScan

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
- IP and Host are logged to stdout during execution
