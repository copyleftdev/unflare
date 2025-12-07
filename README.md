# unflare

A high-performance Cloudflare intelligence toolkit written in Zig.

## Features

- **detect** — Multi-signal Cloudflare detection with confidence scoring
- **probe** — Detailed HTTP response analysis with header highlighting
- **trace** — Parse /cdn-cgi/trace endpoint data
- **origin** — Discover origin IPs via subdomain enumeration
- **favicon** — Generate MMH3 hashes for Shodan/Censys hunting
- **ipcheck** — Check IPs against CDN/WAF ranges (Cloudflare, Fastly, Akamai)

## Installation

### From Source

Requires Zig 0.13+ and OpenSSL development headers.

```bash
# Build
zig build -Doptimize=ReleaseSafe

# Run
./zig-out/bin/unflare --help
```

### Cross-Compilation

```bash
# Linux x86_64
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux

# macOS ARM64
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-macos

# Windows
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-windows
```

## Usage

### Detect Cloudflare

```bash
$ unflare detect cloudflare.com discord.com google.com

Scanning: cloudflare.com
╭─────────────────────── Cloudflare Detection ────────────────────────╮
│   Target        cloudflare.com                                      │
│   Status        ✓ CLOUDFLARE DETECTED                               │
│   Confidence    75%                                                 │
│   Signals       4 detected                                          │
╰─────────────────────────────────────────────────────────────────────╯
  Datacenter: LAX (Los Angeles, US)
```

### Origin Discovery

```bash
$ unflare origin example.com

Origin Discovery: example.com
Scanning subdomains...

┌─────────────────────────────────────────────────────────────────┐
│ Target Analysis                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Target IP:      104.16.132.229                                  │
│ Status:         ✓ Behind Cloudflare                             │
│ Subdomains:     35                                              │
└─────────────────────────────────────────────────────────────────┘

🎯 Potential Origin IPs (2 found):
│ 192.168.1.100    │ mail.example.com              │   80%       │
│ 10.0.0.50        │ dev.example.com               │   80%       │
```

### Favicon Hash

```bash
$ unflare favicon github.com

┌─────────────────────────────────────────────────────────────────┐
│ Favicon Analysis                                                │
├─────────────────────────────────────────────────────────────────┤
│ URL:            https://github.com/favicon.ico                  │
│ Size:           6518                                            │
│ MMH3 Hash:      1848946384                                      │
└─────────────────────────────────────────────────────────────────┘

Search Queries:
  Shodan:  http.favicon.hash:1848946384
```

### IP Check

```bash
$ unflare ipcheck 104.16.1.1 8.8.8.8 151.101.1.140

                 IP Range Check
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━┓
┃ IP            ┃ Provider   ┃ Type ┃ Protected ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━┩
│ 104.16.1.1    │ cloudflare │ waf  │ ✓         │
│ 8.8.8.8       │ -          │ -    │ ✗         │
│ 151.101.1.140 │ fastly     │ cdn  │ ✓         │
└───────────────┴────────────┴──────┴───────────┘
```

## Detection Signals

unflare analyzes multiple signals to detect Cloudflare:

| Signal | Weight | Description |
|--------|--------|-------------|
| Server header | 30% | `server: cloudflare` |
| CF-Ray header | 25% | Unique request ID with datacenter |
| IP range | 20% | IP in Cloudflare's published ranges |
| /cdn-cgi/trace | 15% | Cloudflare trace endpoint |
| CF-Cache-Status | 10% | Cache status header |
| Alt-Svc | 5% | HTTP/3 advertisement |
| NEL | 5% | Network Error Logging |
| CF-Mitigated | 10% | WAF/Bot management |

## Subdomains Checked

Origin discovery checks 35 common subdomains:

- **Direct**: `direct`, `origin`, `backend`, `server`, `real`
- **Mail**: `mail`, `smtp`, `pop`, `imap`, `mx`, `webmail`
- **Dev**: `dev`, `staging`, `test`, `beta`, `uat`
- **API**: `api`, `api2`, `api-internal`
- **Admin**: `admin`, `panel`, `cpanel`, `whm`
- **Other**: `ftp`, `ssh`, `vpn`, `old`, `www2`

## Legal

This tool is for **authorized security testing only**. Always obtain proper authorization before testing third-party infrastructure.

## License

MIT
