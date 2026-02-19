# 📡 Zen Trading Journal v9

A professional trading journal with **live market data** — NSE/BSE indices, F&O option chain, US markets, crypto, and forex — deployed as a static site on GitHub Pages with a Python backend bridge on Oracle Cloud.

---

## 🗂 Repository Structure

```
zen-journal/
├── index.html          ← The entire trading journal (single file)
├── angel_bridge.py     ← Python WebSocket bridge (runs on Oracle VPS)
├── .nojekyll           ← Tells GitHub Pages to skip Jekyll processing
└── README.md           ← This file
```

---

## ⚡ Data Sources

| Source | What it provides | Setup needed |
|---|---|---|
| **CoinGecko** | Crypto prices (BTC, ETH, SOL…) | None — free, auto |
| **Frankfurter** | Forex rates (USD/INR, EUR/USD…) | None — free, auto |
| **Finnhub** | US markets, news, calendar | Free API key |
| **Angel One SmartAPI** | NSE/BSE live ticks, F&O chain, movers | Python bridge on VPS |

---

## 🚀 PART 1 — Deploy to GitHub Pages

### Step 1 — Create GitHub Repository

1. Go to [github.com](https://github.com) → **New repository**
2. Name it: `zen-journal` (or anything you like)
3. Set to **Public** (required for free GitHub Pages)
4. Click **Create repository**

### Step 2 — Upload Files

**Option A — GitHub Web UI (easiest):**
1. In your new repo, click **Add file → Upload files**
2. Upload `index.html`, `angel_bridge.py`, `.nojekyll`, `README.md`
3. Click **Commit changes**

**Option B — Git CLI:**
```bash
git clone https://github.com/YOUR_USERNAME/zen-journal.git
cd zen-journal
# Copy all 4 files into this folder
git add .
git commit -m "Initial deploy"
git push origin main
```

### Step 3 — Enable GitHub Pages

1. In your repo → **Settings** → **Pages** (left sidebar)
2. Under **Source** → select **Deploy from a branch**
3. Branch: **main** | Folder: **/ (root)**
4. Click **Save**
5. Wait ~2 minutes → your journal is live at:
   ```
   https://YOUR_USERNAME.github.io/zen-journal/
   ```

### Step 4 — Add Finnhub API Key (for US markets + news)

1. Go to [finnhub.io/register](https://finnhub.io/register) — free account
2. Copy your API key
3. In the journal → click **⚡ Live Data** (top right)
4. Paste your Finnhub key → click **Save & Activate**

Crypto and forex load automatically without any key.

---

## 🖥 PART 2 — Set Up Oracle VPS (for NSE/F&O live data)

### Step 1 — Create Oracle Cloud Free Account

1. Go to [cloud.oracle.com](https://cloud.oracle.com) → **Start for free**
2. Sign up (credit card required for identity verification, but **Always Free** tier is genuinely free)
3. Choose home region: **ap-mumbai-1** (Mumbai — lowest latency to NSE)

### Step 2 — Create a Free VM Instance

1. Oracle Console → **Compute** → **Instances** → **Create Instance**
2. Settings:
   - **Name:** `zen-bridge`
   - **Image:** Ubuntu 22.04 (Minimal)
   - **Shape:** VM.Standard.E2.1.Micro (**Always Free**)
   - **SSH keys:** Upload your public key (generate with `ssh-keygen` if needed)
3. Click **Create** — wait ~2 minutes
4. Note your instance's **Public IP address**

### Step 3 — Open Port 8765 in Oracle Firewall

**In Oracle Cloud Console:**
1. Go to your instance → **Subnet** → **Security List**
2. **Add Ingress Rules:**
   - Source CIDR: `0.0.0.0/0`
   - Protocol: TCP
   - Destination Port: `8765`
3. Save

**On the VPS itself:**
```bash
ssh ubuntu@YOUR_VPS_IP
sudo iptables -A INPUT -p tcp --dport 8765 -j ACCEPT
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

### Step 4 — Install Dependencies on VPS

```bash
ssh ubuntu@YOUR_VPS_IP

sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip python3-venv git -y

pip3 install smartapi-python websockets pyotp requests
```

### Step 5 — Configure and Run the Bridge

```bash
# Upload angel_bridge.py to VPS
scp angel_bridge.py ubuntu@YOUR_VPS_IP:~/

# SSH into VPS
ssh ubuntu@YOUR_VPS_IP

# Edit the CONFIG section in the script
nano angel_bridge.py
# Fill in: CLIENT_CODE, API_KEY, TOTP_SECRET, MPIN

# Test run
python3 angel_bridge.py
```

You should see:
```
✅ Authenticated.
🟢 Bridge running: ws://0.0.0.0:8765
   Waiting for browser connections…
```

### Step 6 — Connect Journal to VPS Bridge

1. Open your journal at `https://YOUR_USERNAME.github.io/zen-journal/`
2. Go to **📡 Live Markets** tab → click **🔶 Angel One Setup**
3. Fill in:
   - **Client Code, API Key, TOTP Secret, MPIN** (your Angel One credentials)
   - **Bridge Host:** `YOUR_VPS_IP` (the Oracle public IP)
   - **Bridge Port:** `8765`
4. Click **Save & Connect**

---

## 🔒 PART 3 — Enable SSL (wss://) — Required for GitHub Pages

GitHub Pages serves over HTTPS. Browsers **block** unencrypted WebSocket (`ws://`) connections from HTTPS pages. You need `wss://` (secure WebSocket).

### Option A — Cloudflare Tunnel (Easiest, Free, No Domain Needed)

```bash
# On your VPS:

# Download cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Login (opens browser link — copy paste it)
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create zen-bridge

# Create config
mkdir -p ~/.cloudflared
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: zen-bridge
credentials-file: /home/ubuntu/.cloudflared/<TUNNEL_ID>.json
ingress:
  - service: ws://localhost:8765
EOF

# Run bridge in background
nohup python3 ~/angel_bridge.py > ~/bridge.log 2>&1 &

# Run Cloudflare tunnel
cloudflared tunnel run zen-bridge
```

Cloudflare gives you a URL like `https://random-name.trycloudflare.com`.
In the journal → Angel One Setup → set Bridge Host to `random-name.trycloudflare.com` and Port to `443`.

### Option B — Let's Encrypt SSL with a Domain

```bash
# Get a free domain first (e.g. from afraid.org or duckdns.org)
# Point it to your VPS IP

# On your VPS:
sudo apt install certbot -y
sudo certbot certonly --standalone -d yourdomain.com

# Edit angel_bridge.py, set:
# SSL_CERT_PATH = "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
# SSL_KEY_PATH  = "/etc/letsencrypt/live/yourdomain.com/privkey.pem"

python3 angel_bridge.py
```

In the journal → set Bridge Host to `yourdomain.com` → connects via `wss://`.

---

## 🔄 Run Bridge Permanently (Systemd)

```bash
sudo nano /etc/systemd/system/angel-bridge.service
```

Paste:
```ini
[Unit]
Description=Zen Journal Angel One Bridge
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu
ExecStart=/usr/bin/python3 /home/ubuntu/angel_bridge.py
Restart=always
RestartSec=15
Environment=AO_CLIENT_CODE=YOUR_CODE
Environment=AO_API_KEY=YOUR_KEY
Environment=AO_TOTP_SECRET=YOUR_SECRET
Environment=AO_MPIN=YOUR_MPIN

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable angel-bridge
sudo systemctl start angel-bridge

# Check status
sudo systemctl status angel-bridge

# View logs
journalctl -u angel-bridge -f
```

---

## 🛡 Security Notes

- **Credentials are stored only in your browser's localStorage** — never sent to GitHub or any third party
- The Python bridge connects to Angel One using your credentials **from your own VPS** — no intermediary
- Consider adding IP whitelisting to port 8765 if you always use the same IP:
  ```bash
  sudo iptables -A INPUT -p tcp --dport 8765 -s YOUR_HOME_IP -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 8765 -j DROP
  ```
- Angel One API terms restrict data to **personal use only**

---

## 🐛 Troubleshooting

| Problem | Fix |
|---|---|
| Journal loads but no live data | Add Finnhub key via ⚡ Live Data button |
| Angel One not connecting | Check VPS port 8765 is open in OCI Security List |
| `Mixed Content` browser error | You need wss:// — use Cloudflare Tunnel (Part 3A) |
| TOTP authentication fails | Ensure your TOTP_SECRET is the base32 string, not the QR code URL |
| Bridge crashes on start | Run `python3 angel_bridge.py` manually to see error message |
| Session expired mid-day | Bridge auto re-authenticates every 23h — check `bridge.log` |

---

## 📱 Access from Mobile

Once deployed on GitHub Pages, open `https://YOUR_USERNAME.github.io/zen-journal/` on any device. The journal works fully in mobile browsers. Add to home screen for app-like experience:

- **iOS Safari:** Share → Add to Home Screen
- **Android Chrome:** Menu → Add to Home Screen
- 

- # Zen Trading Journal — GitHub Actions Live Feed

NSE/BSE live data via GitHub Actions. No server. No VPS. Completely free.

---

## How it works

```
GitHub Actions (every 1 min, market hours)
    → fetch_market.py logs into Angel One SmartAPI
    → fetches NSE indices, top movers, F&O chain
    → writes data.json to this repo
    → GitHub Pages serves data.json
    → index.html reads data.json every 60s
```

**Crypto, Forex, US markets** load directly from free APIs (CoinGecko, Frankfurter, Finnhub) — no setup needed.

---

## Deploy in 5 steps

### Step 1 — Fork or create repo

Create a **public** GitHub repo (required for free GitHub Pages).

Upload these files to the root:
```
index.html
fetch_market.py
.nojekyll
README.md
.github/
  workflows/
    fetch_market.yml
```

### Step 2 — Enable GitHub Pages

Repo → **Settings → Pages → Source: Deploy from branch → main → / (root)** → Save

Your journal will be live at: `https://YOUR_USERNAME.github.io/YOUR_REPO/`

### Step 3 — Create a GitHub Personal Access Token

1. GitHub → your avatar → **Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Click **Generate new token (classic)**
3. Name: `zen-journal-actions`
4. Expiry: 1 year
5. Scopes: check **repo** (full control)
6. Click **Generate token** — **copy it now** (shown only once)

### Step 4 — Add Secrets

Repo → **Settings → Secrets and variables → Actions → New repository secret**

Add these 5 secrets:

| Secret name | Value |
|---|---|
| `AO_CLIENT_CODE` | Your Angel One login ID (e.g. `A123456`) |
| `AO_API_KEY` | From [smartapi.angelbroking.com](https://smartapi.angelbroking.com) → My Apps → Create App |
| `AO_TOTP_SECRET` | The **base32 text string** shown during TOTP setup in Angel One app (looks like `JBSWY3DPEHPK3PXP`) |
| `AO_MPIN` | Your 4-digit MPIN |
| `GH_PAT` | The Personal Access Token from Step 3 |

> **Where to find AO_TOTP_SECRET:**  
> Angel One app → Profile → My Account → Enable TOTP → it shows a QR code AND a text string below it. Copy the **text string**, not the QR code URL.

### Step 5 — Run workflow manually once

1. Go to your repo → **Actions** tab
2. Click **"Fetch NSE Market Data"** in the left sidebar
3. Click **"Run workflow"** → **"Run workflow"**
4. Watch it run — should take ~30 seconds
5. Once done, `data.json` appears in your repo root
6. Open your journal URL — NSE data loads automatically

---

## Schedule

The workflow runs **every minute, Monday–Friday, 9:15 AM – 3:30 PM IST**.

Outside market hours it writes a `market_status: "closed"` marker but doesn't re-authenticate (saves API calls).

GitHub Actions free tier gives **2,000 minutes/month**. Running every minute for ~375 market hours/month = **~375 runs × 0.5 min each = ~188 minutes/month** — well within the free tier.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Workflow fails with auth error | Check your secrets — especially `AO_TOTP_SECRET` must be the base32 string, not the URL |
| `data.json` not updating | Check Actions tab for error logs |
| Journal shows stale data | data.json age shown in Live Markets → check if workflow is running |
| `Permission denied` on git push | Check `GH_PAT` has `repo` scope and is not expired |
| Workflow not triggering | Go to Actions tab → enable workflows (GitHub sometimes disables them on new repos) |

---

## Files

| File | Purpose |
|---|---|
| `index.html` | The entire trading journal — single file app |
| `fetch_market.py` | Fetches NSE data from Angel One, writes `data.json` |
| `.github/workflows/fetch_market.yml` | GitHub Actions schedule — runs fetch_market.py every minute |
| `data.json` | Auto-generated — do not edit manually |
| `.nojekyll` | Prevents GitHub Pages from processing files with Jekyll |

