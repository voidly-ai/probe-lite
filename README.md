# Voidly Probe Lite

Lightweight censorship monitoring node for **Raspberry Pi**, VPS, and headless Linux.

Zero dependencies — just Node.js. Tests 62 domains for DNS/TCP/TLS/HTTP blocking and reports results to the [Voidly Censorship Index](https://voidly.ai/censorship-index).

## Quick Start

```bash
git clone https://github.com/voidly-ai/probe-lite.git
cd probe-lite
node probe.mjs --register --country US
```

Replace `US` with your [ISO country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) (e.g., `DE`, `GB`, `IN`, `IR`, `BR`).

## Raspberry Pi Setup

### 1. Install Node.js

```bash
# Option A: NodeSource (recommended)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt-get install -y nodejs

# Option B: If that doesn't work
sudo apt-get install -y nodejs npm
```

Verify: `node --version` (needs 18+)

### 2. Download and run

```bash
git clone https://github.com/voidly-ai/probe-lite.git
cd probe-lite
node probe.mjs --register --country US
```

You should see output like:
```
╔══════════════════════════════════════╗
║     Voidly Probe Lite v1.0           ║
║     Censorship monitoring node       ║
╚══════════════════════════════════════╝
  Platform: linux arm
  Hostname: raspberrypi
  Interval: 300s
  Domains:  62
✅ Registered as pi-raspberrypi-a1b2c3d4 (country: US)

[10:30:00 AM] Probing 20 domains...
  ✅ 18 accessible  🚫 2 blocked  ⚠️  0 errors
  🚫 telegram.org — tcp-reset (90%)
  🚫 signal.org — dns-timeout (50%)
  📡 Results submitted to relay
```

### 3. Run 24/7 (auto-start on boot)

```bash
# Edit the service file to match your install path and username
nano voidly-probe.service
# Change User=pi and WorkingDirectory=/home/pi/probe-lite if needed

# Install and enable
sudo cp voidly-probe.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable voidly-probe
sudo systemctl start voidly-probe

# Check it's running
sudo systemctl status voidly-probe

# View logs
journalctl -u voidly-probe -f
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--register` | — | Register as a new probe node (run once) |
| `--country US` | `XX` | Your [ISO country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) |
| `--interval 300` | `300` | Seconds between probe cycles (5 min default) |

After the first run with `--register`, your node ID is saved to `.probe-config.json`. Future runs don't need `--register` again:

```bash
node probe.mjs   # uses saved config
```

## What It Tests

62 domains across 6 categories:

| Category | Domains | Examples |
|----------|---------|----------|
| Social Media | 12 | x.com, facebook.com, youtube.com, tiktok.com |
| Messaging | 8 | whatsapp.com, telegram.org, signal.org |
| News | 12 | bbc.com, nytimes.com, aljazeera.com |
| Privacy/VPN | 10 | torproject.org, protonvpn.com, mullvad.net |
| Human Rights | 8 | amnesty.org, hrw.org, eff.org |
| Tech | 12 | google.com, wikipedia.org, github.com |

Each domain is tested for:
- **DNS blocking** — NXDOMAIN, DNS timeout, poisoned responses
- **TCP blocking** — Connection reset, refused, timeout
- **TLS interference** — Certificate errors, TLS reset, MITM
- **HTTP blocking** — Status 451, suspicious redirects, block pages

Results rotate through all 62 domains (20 per cycle) and are submitted to the Voidly relay.

## Troubleshooting

**"command not found: node"** — Install Node.js (see step 1 above)

**"Submission failed"** — Your probe still works locally. Results will be submitted when the relay is reachable. Check your internet connection.

**All domains show as blocked** — Your network might actually be blocking them, or your DNS is misconfigured. Try `nslookup google.com` to verify DNS works.

**Permission denied** — Make sure the script is executable: `chmod +x probe.mjs`

**Want to change your country code?** — Delete `.probe-config.json` and re-run with `--register --country XX`

## How It Helps

Every probe cycle contributes data to the [Voidly Censorship Index](https://voidly.ai/censorship-index) — a live ranking of internet censorship across 119+ countries. More nodes = better data = more accurate censorship detection.

Join the probe network: [voidly.ai/probes](https://voidly.ai/probes)

## Requirements

- **Node.js 18+** (no npm packages needed)
- Internet connection
- Works on: Raspberry Pi (ARM), Linux (x64/ARM), macOS, Windows

## License

MIT
