# Wireshark Detection Filters Reference

Display filters used across all scenarios in this project. Apply in the Wireshark filter bar — green background indicates a valid filter, red indicates a syntax error.

---

## Network Reconnaissance

| Scenario | Filter | Purpose |
|----------|--------|---------|
| Host discovery | `icmp` | All ICMP traffic |
| Host discovery — target only | `icmp and ip.addr == 192.168.110.130` | Isolate Ubuntu ICMP conversation |
| Port scan — all to target | `tcp and ip.dst == 192.168.110.130` | All TCP probes hitting the target |
| Port scan — open port sequence | `tcp and ip.addr == 192.168.110.130 and tcp.port == 22` | Isolate SYN → SYN-ACK → RST half-open sequence |
| Service enumeration | `tcp and ip.addr == 192.168.110.130` | Full bidirectional TCP including banner exchange |
| Active recon — all protocols | `ip.addr == 192.168.110.130` | All protocols in the aggressive scan |
| Active recon — HTTP NSE only | `http and ip.addr == 192.168.110.130` | NSE web path probes only |
| Active recon — FTP probe only | `ftp and ip.addr == 192.168.110.130` | NSE FTP anonymous probe only |

---

## Authentication Attacks

| Scenario | Filter | Purpose |
|----------|--------|---------|
| SSH credential attack | `tcp.port == 22` | All SSH traffic including handshake and encrypted payload |
| FTP credential attack | `ftp` | FTP commands only — filters out TCP ACK noise |
| FTP session exposure | `ftp` | FTP commands including PASS in plaintext |
| HTTP auth attack | `http` | All HTTP requests and responses |
| HTTP requests only | `http.request` | Outbound GET requests with Authorization headers |
| HTTP 401 responses | `http.response.code == 401` | Failed authentication attempts |
| HTTP 200 responses | `http.response.code == 200` | Successful requests |

---

## Protocol Analysis

| Scenario | Filter | Purpose |
|----------|--------|---------|
| FTP session stream | `ftp` | Plaintext FTP commands for comparison |
| SSH session stream | `tcp.port == 22` | Encrypted SSH traffic for comparison |
| HTTP traffic | `http` | All HTTP requests and responses |
| Normal TCP handshake | `tcp.flags.syn == 1` | SYN and SYN-ACK packets — handshake initiation |
| SYN scan handshake | `tcp and ip.addr == 192.168.110.130 and tcp.port == 22` | Three-packet half-open sequence |
| DNS all | `dns` | All DNS queries and responses |
| DNS NXDOMAIN only | `dns.flags.rcode == 3` | Non-Existent Domain responses |
| DNS to external resolver | `dns and ip.dst == 8.8.8.8` | Queries bypassing the internal resolver |

---

## General Purpose Filters

| Filter | Purpose |
|--------|---------|
| `ip.addr == 192.168.110.130` | All traffic involving the target host |
| `ip.src == 192.168.110.132` | Traffic originating from the attack platform |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | SYN-only packets (excludes SYN-ACK) |
| `tcp.flags.reset == 1` | RST packets — connection aborts |
| `tcp.flags.fin == 1` | FIN packets — graceful connection close |
| `tcp.window_size_value == 1024` | Nmap SYN probe fingerprint |
| `!arp` | Suppress ARP traffic for cleaner view |
| `frame.len > 1000` | Large packets — useful for isolating data transfers |

---

## Composite Filters

Combining conditions for more targeted analysis:

```wireshark
# Traffic between two specific hosts only
ip.addr == 192.168.110.132 && ip.addr == 192.168.110.130

# HTTP traffic excluding 200 OK responses
http && http.response.code != 200

# DNS NXDOMAIN from a specific source
dns.flags.rcode == 3 && ip.src == 192.168.91.131

# Nmap SYN probe signature — Win=1024 with SYN flag
tcp.flags.syn == 1 && tcp.window_size_value == 1024

# FTP authentication commands only
ftp && (ftp.request.command == "USER" || ftp.request.command == "PASS")

# SSH connections — exclude established encrypted traffic
tcp.port == 22 && tcp.flags.syn == 1
```

---

## Filter Syntax Reference

| Operator | Meaning | Example |
|----------|---------|---------|
| `==` | Equals | `tcp.port == 22` |
| `!=` | Not equals | `http.response.code != 200` |
| `>` / `<` | Greater / Less than | `frame.len > 1000` |
| `&&` | AND | `tcp.port == 22 && ip.src == 192.168.110.132` |
| `\|\|` | OR | `tcp.port == 21 \|\| tcp.port == 22` |
| `!` | NOT | `!arp` |
| `contains` | String contains | `http.user_agent contains "Hydra"` |
