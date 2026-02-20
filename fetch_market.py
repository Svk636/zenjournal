#!/usr/bin/env python3
"""
fetch_market.py - Angel One SmartAPI data fetcher for Zen Trading Journal
Runs via GitHub Actions every minute during NSE market hours.
Writes data.json to repo root (served by GitHub Pages).

Required GitHub Secrets:
  AO_CLIENT_CODE   - Your Angel One login ID
  AO_API_KEY       - From smartapi.angelbroking.com
  AO_TOTP_SECRET   - Base32 TOTP secret from Angel One
  AO_MPIN          - Your 4-digit MPIN
  GH_PAT           - GitHub Personal Access Token (repo scope)
"""
import os, json, time, hmac, hashlib, struct, base64, math
from datetime import datetime, timezone
import urllib.request, urllib.error

# -- Config from GitHub Secrets ------------------------------------------
CLIENT_CODE  = os.environ["AO_CLIENT_CODE"]
API_KEY      = os.environ["AO_API_KEY"]
TOTP_SECRET  = os.environ["AO_TOTP_SECRET"]
MPIN         = os.environ["AO_MPIN"]
GH_PAT       = os.environ["GH_PAT"]
GH_REPO      = os.environ.get("GITHUB_REPOSITORY", "")
GH_BRANCH    = os.environ.get("GH_BRANCH", "main")

BASE_URL = "https://apiconnect.angelbroking.com"

# -- TOTP (RFC 6238) ------------------------------------------------------
def generate_totp(secret_b32: str) -> str:
    secret = secret_b32.upper().replace(" ", "")
    secret += "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret)
    counter = struct.pack(">Q", int(time.time()) // 30)
    hmac_hash = hmac.new(key, counter, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)

# -- Angel One API helpers ------------------------------------------------
def ao_post(path: str, payload: dict, extra_headers: dict = None) -> dict:
    url = BASE_URL + path
    data = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-PrivateKey": API_KEY,
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

def ao_get(path: str, token: str) -> dict:
    url = BASE_URL + path
    req = urllib.request.Request(url,
          headers={
              "Authorization": f"Bearer {token}",
              "Content-Type": "application/json",
              "Accept": "application/json",
              "X-UserType": "USER",
              "X-SourceID": "WEB",
              "X-ClientLocalIP": "127.0.0.1",
              "X-ClientPublicIP": "127.0.0.1",
              "X-MACAddress": "00:00:00:00:00:00",
              "X-PrivateKey": API_KEY,
          })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

# -- Login ----------------------------------------------------------------
def login() -> str:
    totp = generate_totp(TOTP_SECRET)
    resp = ao_post("/rest/auth/angelbroking/user/v1/loginByPassword", {
        "clientcode": CLIENT_CODE,
        "password": MPIN,
        "totp": totp
    })
    if not resp.get("status"):
        raise RuntimeError(f"Login failed: {resp.get('message', 'unknown error')}")
    return resp["data"]["jwtToken"]

# -- Fetch NSE indices (POST-based) ---------------------------------------
INDEX_TOKENS = {
    "NIFTY50":    "99926000",
    "BANKNIFTY":  "99926009",
    "SENSEX":     "99919000",
    "NIFTYIT":    "99926048",
    "MIDCPNIFTY": "99926013",
    "INDIAVIX":   "99919003",
}

def fetch_indices(token: str) -> dict:
    indices = {}
    for sym, tok in INDEX_TOKENS.items():
        try:
            resp = ao_post(
                "/rest/secure/angelbroking/market/v1/quote",
                {"mode": "FULL", "exchangeTokens": {"NSE": [tok]}},
                {"Authorization": f"Bearer {token}"}
            )
            if resp.get("status") and resp.get("data", {}).get("fetched"):
                d     = resp["data"]["fetched"][0]
                ltp   = float(d.get("ltp", 0))
                close = float(d.get("close", ltp) or ltp)
                chg_pct = ((ltp - close) / close * 100) if close else 0
                indices[sym] = {
                    "ltp":   round(ltp, 2),
                    "chg":   round(chg_pct, 2),
                    "close": round(close, 2),
                }
        except Exception as e:
            print(f"  Warning Index {sym}: {e}")
    return indices

# -- Fetch top movers (POST-based) ----------------------------------------
NIFTY50_SYMBOLS = [
    ("RELIANCE","2885"),  ("TCS","11536"),      ("HDFCBANK","1333"),
    ("INFY","1594"),      ("ICICIBANK","4963"),  ("BHARTIARTL","10604"),
    ("ITC","1660"),       ("SBIN","3045"),       ("WIPRO","3787"),
    ("NESTLEIND","17963"),("BAJFINANCE","317"),  ("LT","11483"),
    ("HCLTECH","7229"),   ("TITAN","3506"),      ("KOTAKBANK","1922"),
    ("ADANIENT","25"),    ("MARUTI","10999"),    ("SUNPHARMA","3351"),
    ("ASIANPAINT","236"), ("ULTRACEMCO","2585"),
]

def fetch_movers(token: str) -> dict:
    gainers, losers = [], []
    try:
        tokens_list = [t for _, t in NIFTY50_SYMBOLS]
        resp = ao_post(
            "/rest/secure/angelbroking/market/v1/quote",
            {"mode": "LTP", "exchangeTokens": {"NSE": tokens_list}},
            {"Authorization": f"Bearer {token}"}
        )
        if resp.get("status") and resp.get("data", {}).get("fetched"):
            sym_map = {t: s for s, t in NIFTY50_SYMBOLS}
            rows = []
            for d in resp["data"]["fetched"]:
                sym   = sym_map.get(d.get("symbolToken", ""), d.get("tradingSymbol", ""))
                ltp   = float(d.get("ltp", 0))
                close = float(d.get("close", ltp) or ltp)
                chg   = ((ltp - close) / close * 100) if close else 0
                rows.append({"symbol": sym, "ltp": round(ltp, 2), "chg": round(chg, 2), "series": "EQ"})
            rows.sort(key=lambda x: x["chg"], reverse=True)
            gainers = rows[:10]
            losers  = rows[-10:][::-1]
    except Exception as e:
        print(f"  Warning Movers: {e}")
    return {"gainers": gainers, "losers": losers}

# -- Fetch F&O option chain (NIFTY) ---------------------------------------
def fetch_fo_chain(token: str) -> dict:
    try:
        resp = ao_post(
            "/rest/secure/angelbroking/market/v1/optionChain",
            {"name": "NIFTY", "expirydate": "", "strikecount": 12},
            {"Authorization": f"Bearer {token}"}
        )
        if not (resp.get("status") and resp.get("data")):
            return {}
        oc   = resp["data"]
        spot = float(oc.get("underlyingLTP", 22500))
        atm  = round(spot / 50) * 50
        chain_data = oc.get("OC", {})
        strikes = []
        call_oi_total = put_oi_total = 0
        for strike_price, opt in sorted(chain_data.items(), key=lambda x: float(x[0])):
            sp      = float(strike_price)
            c       = opt.get("CE", {})
            p       = opt.get("PE", {})
            call_oi = int(c.get("openInterest", 0))
            put_oi  = int(p.get("openInterest", 0))
            call_oi_total += call_oi
            put_oi_total  += put_oi
            strikes.append({
                "strike":      sp,
                "atm":         abs(sp - atm) < 1,
                "callOI":      call_oi,
                "callLTP":     float(c.get("lastPrice", 0)),
                "callPrevLTP": float(c.get("closePrice", 0)),
                "putOI":       put_oi,
                "putLTP":      float(p.get("lastPrice", 0)),
                "putPrevLTP":  float(p.get("closePrice", 0)),
            })
        pcr = (put_oi_total / call_oi_total) if call_oi_total else 1.0
        # Max pain
        max_pain     = atm
        min_pain_val = float("inf")
        for s in strikes:
            pain = sum(
                max(0, (s["strike"] - x["strike"])) * x["callOI"] +
                max(0, (x["strike"] - s["strike"])) * x["putOI"]
                for x in strikes
            )
            if pain < min_pain_val:
                min_pain_val = pain
                max_pain     = s["strike"]
        return {
            "pcr":     round(pcr, 3),
            "maxpain": max_pain,
            "totaloi": call_oi_total + put_oi_total,
            "spot":    round(spot, 2),
            "chain":   strikes,
        }
    except Exception as e:
        print(f"  Warning F&O chain: {e}")
        return {}

# -- Push data.json to GitHub ---------------------------------------------
def push_to_github(payload: dict):
    content = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()
    path = f"https://api.github.com/repos/{GH_REPO}/contents/data.json"

    # Get current SHA (needed for update)
    sha = None
    try:
        req = urllib.request.Request(path, headers={
            "Authorization": f"token {GH_PAT}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ZenJournal-Actions",
        })
        with urllib.request.urlopen(req, timeout=10) as r:
            sha = json.loads(r.read()).get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    body = {
        "message": f"data: market snapshot {payload['timestamp']}",
        "content": content,
        "branch":  GH_BRANCH,
    }
    if sha:
        body["sha"] = sha

    data = json.dumps(body).encode()
    req  = urllib.request.Request(path, data=data, method="PUT", headers={
        "Authorization": f"token {GH_PAT}",
        "Accept":        "application/vnd.github.v3+json",
        "Content-Type":  "application/json",
        "User-Agent":    "ZenJournal-Actions",
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        resp = json.loads(r.read())
    print(f"  Pushed data.json (SHA: {resp.get('content', {}).get('sha', '?')[:7]})")

# -- Market hours check (IST) ---------------------------------------------
def is_market_open() -> bool:
    from datetime import timedelta
    ist = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
    if ist.weekday() >= 5:
        return False
    h, m = ist.hour, ist.minute
    return (h == 9 and m >= 0) or (9 < h < 15) or (h == 15 and m <= 30)

# -- Main -----------------------------------------------------------------
def main():
    print(f"ZenJournal fetch_market.py - {datetime.utcnow().isoformat()}Z")

    if not is_market_open():
        print("  Market closed - skipping fetch")
        return

    print("  Logging in to Angel One...")
    token = login()
    print("  Login OK")

    print("  Fetching indices...")
    indices = fetch_indices(token)
    print(f"  {len(indices)} indices fetched: {list(indices.keys())}")

    print("  Fetching movers...")
    movers = fetch_movers(token)
    print(f"  {len(movers.get('gainers',[]))} gainers, {len(movers.get('losers',[]))} losers")

    print("  Fetching F&O chain...")
    fo = fetch_fo_chain(token)
    print(f"  F&O: PCR={fo.get('pcr','-')}, MaxPain={fo.get('maxpain','-')}")

    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source":    "Angel One SmartAPI via GitHub Actions",
        "indices":   indices,
        "movers":    movers,
        "fo":        fo,
    }

    print("  Pushing to GitHub...")
    push_to_github(payload)
    print("  Done!")

if __name__ == "__main__":
    main()
