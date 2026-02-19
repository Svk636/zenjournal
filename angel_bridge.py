#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║     Zen Trading Journal — Angel One SmartAPI Bridge          ║
║     Deploy on Oracle Cloud Free VPS (Ubuntu)                 ║
╚══════════════════════════════════════════════════════════════╝

SETUP ON ORACLE VPS (Ubuntu 22.04):
────────────────────────────────────
1. Install dependencies:
   sudo apt update && sudo apt install python3-pip python3-venv -y
   pip3 install smartapi-python websockets pyotp requests

2. Fill in your credentials in the CONFIG section below.

3. For SSL/WSS (required when journal is on GitHub Pages):
   sudo apt install certbot -y
   sudo certbot certonly --standalone -d yourdomain.com
   Set SSL_CERT_PATH and SSL_KEY_PATH below.
   
   OR use a free domain from afraid.org / duckdns.org + certbot.
   
   ALTERNATIVE (no domain): Use Cloudflare Tunnel (free, no SSL setup needed)
   → See CLOUDFLARE TUNNEL section at bottom of this file.

4. Open firewall port:
   sudo iptables -A INPUT -p tcp --dport 8765 -j ACCEPT
   (Oracle Cloud: also open port 8765 in Security List in the OCI console)

5. Run:
   python3 angel_bridge.py
   
   To run permanently in background:
   nohup python3 angel_bridge.py > bridge.log 2>&1 &
   
   Better — use systemd (see bottom of file).

WHAT THIS DOES:
───────────────
• Authenticates with Angel One SmartAPI using TOTP
• Fetches live LTP for NSE indices every 5 seconds
• Optionally streams F&O option chain data
• Broadcasts all data to connected browser clients via WebSocket
• Auto-reconnects if Angel One session expires
"""

import asyncio
import json
import logging
import ssl
import sys
import time
import os
from datetime import datetime

import websockets

try:
    from SmartApi import SmartConnect
except ImportError:
    print("ERROR: smartapi-python not installed.")
    print("Run: pip3 install smartapi-python websockets pyotp requests")
    sys.exit(1)

try:
    import pyotp
except ImportError:
    print("ERROR: pyotp not installed. Run: pip3 install pyotp")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
#   CONFIG — Fill these in
# ══════════════════════════════════════════════════════════════════

CLIENT_CODE  = os.environ.get("AO_CLIENT_CODE",  "YOUR_CLIENT_CODE")
API_KEY      = os.environ.get("AO_API_KEY",       "YOUR_API_KEY")
TOTP_SECRET  = os.environ.get("AO_TOTP_SECRET",   "YOUR_TOTP_BASE32_SECRET")
MPIN         = os.environ.get("AO_MPIN",          "YOUR_4_DIGIT_MPIN")

# Bridge server config
BRIDGE_HOST  = "0.0.0.0"   # Listen on all interfaces (required for VPS)
BRIDGE_PORT  = 8765

# SSL config (for wss:// — required when journal is hosted on HTTPS like GitHub Pages)
# Set to None to disable SSL (use ws:// — only works for local/http access)
SSL_CERT_PATH = os.environ.get("SSL_CERT", None)   # e.g. "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
SSL_KEY_PATH  = os.environ.get("SSL_KEY",  None)   # e.g. "/etc/letsencrypt/live/yourdomain.com/privkey.pem"

# How often to poll Angel One for prices (seconds)
POLL_INTERVAL = 5

# ══════════════════════════════════════════════════════════════════
#   NSE / BSE TOKEN MAP
#   Add more tokens from the Angel One scrip master CSV:
#   https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json
# ══════════════════════════════════════════════════════════════════

NSE_TOKENS = {
    "NIFTY":       {"token": "99926000", "exchange": "NSE", "symbolname": "Nifty 50"},
    "BANKNIFTY":   {"token": "99926009", "exchange": "NSE", "symbolname": "Nifty Bank"},
    "FINNIFTY":    {"token": "99926037", "exchange": "NSE", "symbolname": "Nifty Fin Service"},
    "MIDCPNIFTY":  {"token": "99926074", "exchange": "NSE", "symbolname": "Nifty Midcap"},
    "SENSEX":      {"token": "1",        "exchange": "BSE", "symbolname": "Sensex"},
    "INDIAVIX":    {"token": "99919000", "exchange": "NSE", "symbolname": "India VIX"},
    "NIFTYIT":     {"token": "99926009", "exchange": "NSE", "symbolname": "Nifty IT"},
}

# NSE stocks for top movers
NSE_STOCKS = {
    "RELIANCE":   {"token": "2885",  "exchange": "NSE"},
    "TCS":        {"token": "11536", "exchange": "NSE"},
    "HDFCBANK":   {"token": "1333",  "exchange": "NSE"},
    "INFY":       {"token": "1594",  "exchange": "NSE"},
    "ICICIBANK":  {"token": "4963",  "exchange": "NSE"},
    "WIPRO":      {"token": "3787",  "exchange": "NSE"},
    "AXISBANK":   {"token": "5900",  "exchange": "NSE"},
    "KOTAKBANK":  {"token": "1922",  "exchange": "NSE"},
    "LT":         {"token": "11483", "exchange": "NSE"},
    "SBIN":       {"token": "3045",  "exchange": "NSE"},
    "BAJFINANCE": {"token": "317",   "exchange": "NSE"},
    "MARUTI":     {"token": "10999", "exchange": "NSE"},
    "TITAN":      {"token": "3506",  "exchange": "NSE"},
    "SUNPHARMA":  {"token": "3351",  "exchange": "NSE"},
    "ADANIENT":   {"token": "25",    "exchange": "NSE"},
    "HCLTECH":    {"token": "7229",  "exchange": "NSE"},
    "BHARTIARTL": {"token": "10604", "exchange": "NSE"},
    "ITC":        {"token": "1660",  "exchange": "NSE"},
    "ASIANPAINT": {"token": "236",   "exchange": "NSE"},
    "HINDUNILVR": {"token": "1394",  "exchange": "NSE"},
}

# ══════════════════════════════════════════════════════════════════
#   LOGGING
# ══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("bridge.log", mode="a"),
    ]
)
log = logging.getLogger("AngelBridge")

# ══════════════════════════════════════════════════════════════════
#   STATE
# ══════════════════════════════════════════════════════════════════

connected_clients: set = set()
angel_obj = None
auth_token = None
prev_prices: dict = {}      # symbol -> ltp at prev close (for % change)
session_start: float = 0    # epoch when last authenticated


# ══════════════════════════════════════════════════════════════════
#   ANGEL ONE AUTH
# ══════════════════════════════════════════════════════════════════

def authenticate() -> SmartConnect:
    global angel_obj, auth_token, session_start

    if CLIENT_CODE == "YOUR_CLIENT_CODE":
        log.error("❌ Please fill in your credentials in the CONFIG section of angel_bridge.py")
        sys.exit(1)

    totp_code = pyotp.TOTP(TOTP_SECRET).now()
    log.info(f"Authenticating as {CLIENT_CODE} (TOTP: {totp_code})")

    obj = SmartConnect(api_key=API_KEY)
    session = obj.generateSession(CLIENT_CODE, MPIN, totp_code)

    if not session or session.get("status") is False:
        raise RuntimeError(f"Auth failed: {session.get('message', 'Unknown error')}")

    angel_obj = obj
    auth_token = session["data"]["jwtToken"]
    session_start = time.time()
    log.info(f"✅ Authenticated. Session valid for ~24h")
    return obj


def ensure_auth():
    """Re-authenticate if session is older than 23 hours."""
    global session_start
    if time.time() - session_start > 23 * 3600:
        log.info("Session approaching expiry, re-authenticating…")
        authenticate()


# ══════════════════════════════════════════════════════════════════
#   DATA FETCHING
# ══════════════════════════════════════════════════════════════════

def fetch_ltp(exchange: str, symbol_name: str, token: str) -> float | None:
    try:
        resp = angel_obj.ltpData(exchange, symbol_name, token)
        if resp and resp.get("status") and resp.get("data"):
            return float(resp["data"]["ltp"])
    except Exception as e:
        log.debug(f"LTP error for {symbol_name}: {e}")
    return None


def fetch_all_indices() -> list[dict]:
    """Fetch LTP for all configured indices. Returns list of tick dicts."""
    ticks = []
    for sym, info in NSE_TOKENS.items():
        ltp = fetch_ltp(info["exchange"], info["symbolname"], info["token"])
        if ltp is None:
            continue
        prev = prev_prices.get(sym, ltp)
        chg_pct = round((ltp - prev) / prev * 100, 2) if prev else 0.0
        ticks.append({
            "symbol":   sym,
            "ltp":      ltp,
            "chg":      chg_pct,
            "exchange": info["exchange"],
        })
    return ticks


def fetch_movers() -> dict:
    """Fetch LTP for all NSE stocks and compute gainers/losers."""
    results = []
    for sym, info in NSE_STOCKS.items():
        ltp = fetch_ltp(info["exchange"], sym, info["token"])
        if ltp is None:
            continue
        prev = prev_prices.get(sym, ltp)
        chg = round((ltp - prev) / prev * 100, 2) if prev else 0.0
        results.append({"symbol": sym, "ltp": ltp, "chg": chg, "series": "EQ"})

    gainers = sorted([r for r in results if r["chg"] > 0], key=lambda x: -x["chg"])
    losers  = sorted([r for r in results if r["chg"] < 0], key=lambda x: x["chg"])
    return {"gainers": gainers[:10], "losers": losers[:10]}


def fetch_fo_chain(symbol: str = "NIFTY", expiry_type: str = "weekly") -> dict | None:
    """Fetch F&O option chain from Angel One."""
    try:
        resp = angel_obj.optionChain(symbol, expiry_type)
        if not resp or not resp.get("status"):
            return None
        data = resp.get("data", {})
        spot = float(data.get("underlyingValue", 0))
        chain_data = data.get("optionChainData", [])

        strikes = []
        for row in chain_data:
            call = row.get("CE", {})
            put  = row.get("PE", {})
            strike = float(row.get("strikePrice", 0))
            strikes.append({
                "strike":       strike,
                "atm":          abs(strike - spot) < 51,
                "callOI":       int(call.get("openInterest", 0)),
                "callLTP":      float(call.get("lastPrice", 0)),
                "callPrevLTP":  float(call.get("previousClose", 0)),
                "putOI":        int(put.get("openInterest", 0)),
                "putLTP":       float(put.get("lastPrice", 0)),
                "putPrevLTP":   float(put.get("previousClose", 0)),
            })

        total_call_oi = sum(s["callOI"] for s in strikes) or 1
        total_put_oi  = sum(s["putOI"]  for s in strikes)
        pcr = round(total_put_oi / total_call_oi, 2)

        # Max pain: strike where total option pain is minimised
        def pain(strike):
            c = sum(max(0, strike - s["strike"]) * s["callOI"] for s in strikes)
            p = sum(max(0, s["strike"] - strike) * s["putOI"]  for s in strikes)
            return c + p
        max_pain_strike = min(strikes, key=lambda s: pain(s["strike"]))["strike"] if strikes else 0

        return {
            "strikes":   strikes,
            "pcr":       pcr,
            "maxPain":   max_pain_strike,
            "totalOI":   total_call_oi + total_put_oi,
            "spotPrice": spot,
            "symbol":    symbol,
            "expiry":    expiry_type,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        log.error(f"F&O chain error for {symbol}: {e}")
        return None


# ══════════════════════════════════════════════════════════════════
#   WEBSOCKET BROADCAST
# ══════════════════════════════════════════════════════════════════

async def broadcast(message: dict):
    if not connected_clients:
        return
    payload = json.dumps(message)
    dead = set()
    for ws in connected_clients.copy():
        try:
            await ws.send(payload)
        except websockets.exceptions.ConnectionClosed:
            dead.add(ws)
        except Exception as e:
            log.debug(f"Broadcast error: {e}")
            dead.add(ws)
    connected_clients -= dead


# ══════════════════════════════════════════════════════════════════
#   PRICE POLLING LOOP
# ══════════════════════════════════════════════════════════════════

async def price_loop():
    movers_counter = 0

    while True:
        try:
            ensure_auth()

            # Fetch indices every cycle
            ticks = await asyncio.get_event_loop().run_in_executor(None, fetch_all_indices)
            if ticks:
                await broadcast({"type": "tick", "data": ticks})
                log.info(f"📡 Broadcast {len(ticks)} index ticks → {len(connected_clients)} client(s)")

            # Fetch movers every 5th cycle (~25s)
            movers_counter += 1
            if movers_counter >= 5:
                movers_counter = 0
                if connected_clients:
                    movers = await asyncio.get_event_loop().run_in_executor(None, fetch_movers)
                    await broadcast({"type": "movers", "data": movers})
                    log.info(f"📊 Broadcast movers: {len(movers['gainers'])} gainers, {len(movers['losers'])} losers")

        except Exception as e:
            log.error(f"Price loop error: {e}")
            try:
                await asyncio.get_event_loop().run_in_executor(None, authenticate)
            except Exception as ae:
                log.error(f"Re-auth failed: {ae}")

        await asyncio.sleep(POLL_INTERVAL)


# ══════════════════════════════════════════════════════════════════
#   WEBSOCKET CLIENT HANDLER
# ══════════════════════════════════════════════════════════════════

async def handler(websocket, path=None):
    client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    connected_clients.add(websocket)
    log.info(f"🔌 Client connected from {client_ip} — total: {len(connected_clients)}")

    # Send a hello with current status
    await websocket.send(json.dumps({
        "type": "hello",
        "message": "Zen Journal Bridge connected",
        "symbols": list(NSE_TOKENS.keys()),
        "timestamp": datetime.now().isoformat(),
    }))

    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                msg_type = msg.get("type")

                if msg_type == "subscribe":
                    syms = msg.get("symbols", [])
                    log.info(f"Subscribe request: {syms} from {client_ip}")
                    await websocket.send(json.dumps({"type": "subscribed", "symbols": syms}))

                elif msg_type == "fochain":
                    sym = msg.get("symbol", "NIFTY")
                    exp = msg.get("expiry", "weekly")
                    log.info(f"F&O chain request: {sym} {exp}")
                    chain = await asyncio.get_event_loop().run_in_executor(
                        None, fetch_fo_chain, sym, exp
                    )
                    await websocket.send(json.dumps({
                        "type": "fochain",
                        "data": chain,
                        "error": None if chain else "No data returned from Angel One"
                    }))

                elif msg_type == "ping":
                    await websocket.send(json.dumps({"type": "pong"}))

            except json.JSONDecodeError:
                log.debug(f"Invalid JSON from {client_ip}")
            except Exception as e:
                log.error(f"Handler error: {e}")

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.discard(websocket)
        log.info(f"🔌 Client disconnected from {client_ip} — total: {len(connected_clients)}")


# ══════════════════════════════════════════════════════════════════
#   MAIN
# ══════════════════════════════════════════════════════════════════

async def main():
    log.info("=" * 60)
    log.info("  Zen Trading Journal — Angel One Bridge")
    log.info(f"  Version: 1.0  |  Port: {BRIDGE_PORT}")
    log.info("=" * 60)

    # Authenticate with Angel One
    try:
        authenticate()
    except Exception as e:
        log.error(f"❌ Authentication failed: {e}")
        log.error("→ Check CLIENT_CODE, API_KEY, TOTP_SECRET, MPIN in the CONFIG section")
        sys.exit(1)

    # Build SSL context if certs are provided
    ssl_context = None
    if SSL_CERT_PATH and SSL_KEY_PATH:
        if not os.path.exists(SSL_CERT_PATH):
            log.error(f"❌ SSL cert not found: {SSL_CERT_PATH}")
            sys.exit(1)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT_PATH, SSL_KEY_PATH)
        protocol = "wss"
        log.info(f"🔒 SSL enabled — cert: {SSL_CERT_PATH}")
    else:
        protocol = "ws"
        log.warning("⚠  SSL not configured — using plain ws://")
        log.warning("   GitHub Pages (HTTPS) REQUIRES wss:// — add SSL certs or use Cloudflare Tunnel")

    # Start WebSocket server
    server = await websockets.serve(
        handler,
        BRIDGE_HOST,
        BRIDGE_PORT,
        ssl=ssl_context,
        ping_interval=30,
        ping_timeout=10,
    )

    log.info(f"🟢 Bridge running: {protocol}://{BRIDGE_HOST}:{BRIDGE_PORT}")
    log.info(f"   Polling {len(NSE_TOKENS)} indices every {POLL_INTERVAL}s")
    log.info(f"   Tracking {len(NSE_STOCKS)} NSE stocks for movers")
    log.info("   Waiting for browser connections…")
    log.info("   Press Ctrl+C to stop")

    # Run server + price loop concurrently
    await asyncio.gather(
        server.wait_closed(),
        price_loop(),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("\n👋 Bridge stopped.")


# ══════════════════════════════════════════════════════════════════
#   SYSTEMD SERVICE (run as permanent background service)
# ══════════════════════════════════════════════════════════════════
#
#   Create /etc/systemd/system/angel-bridge.service:
#
#   [Unit]
#   Description=Zen Journal Angel One Bridge
#   After=network.target
#
#   [Service]
#   User=ubuntu
#   WorkingDirectory=/home/ubuntu/zen-journal
#   ExecStart=/usr/bin/python3 /home/ubuntu/zen-journal/angel_bridge.py
#   Restart=always
#   RestartSec=10
#   Environment=AO_CLIENT_CODE=your_code
#   Environment=AO_API_KEY=your_key
#   Environment=AO_TOTP_SECRET=your_secret
#   Environment=AO_MPIN=your_mpin
#   Environment=SSL_CERT=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
#   Environment=SSL_KEY=/etc/letsencrypt/live/yourdomain.com/privkey.pem
#
#   [Install]
#   WantedBy=multi-user.target
#
#   Then:
#   sudo systemctl daemon-reload
#   sudo systemctl enable angel-bridge
#   sudo systemctl start angel-bridge
#   sudo systemctl status angel-bridge
#
# ══════════════════════════════════════════════════════════════════
#   CLOUDFLARE TUNNEL (easiest — no SSL setup, no domain needed)
# ══════════════════════════════════════════════════════════════════
#
#   If you don't want to deal with SSL certs, use Cloudflare Tunnel:
#
#   1. Install cloudflared on VPS:
#      wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
#      chmod +x cloudflared-linux-amd64
#      sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
#
#   2. Login: cloudflared tunnel login
#
#   3. Create tunnel: cloudflared tunnel create zen-bridge
#
#   4. Create config ~/.cloudflared/config.yml:
#      tunnel: zen-bridge
#      credentials-file: /home/ubuntu/.cloudflared/TUNNEL_ID.json
#      ingress:
#        - hostname: bridge.yourdomain.com
#          service: ws://localhost:8765
#        - service: http_status:404
#
#   5. Run: cloudflared tunnel run zen-bridge
#
#   6. In the journal, set bridge host to: bridge.yourdomain.com:443
#      (Cloudflare handles HTTPS/WSS automatically)
#
# ══════════════════════════════════════════════════════════════════
