#!/usr/bin/env python3
"""
fetch_market.py — Zen Trading Journal data fetcher
Runs via GitHub Actions every minute during NSE market hours.
Writes data.json to repo root, served by GitHub Pages.

Secrets required (GitHub repo → Settings → Secrets → Actions):
  AO_CLIENT_CODE   — Angel One login ID
  AO_API_KEY       — From smartapi.angelbroking.com → My Apps
  AO_TOTP_SECRET   — Base32 TOTP secret (not the QR code, the text string)
  AO_MPIN          — 4-digit MPIN
  GH_PAT           — GitHub Personal Access Token (repo scope) — for git push
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

import pyotp
import requests

# ── CONFIG ─────────────────────────────────────────────────────────────────
CLIENT_CODE  = os.environ["AO_CLIENT_CODE"]
API_KEY      = os.environ["AO_API_KEY"]
TOTP_SECRET  = os.environ["AO_TOTP_SECRET"]
MPIN         = os.environ["AO_MPIN"]

BASE_URL = "https://apiconnect.angelbroking.com"

HEADERS_BASE = {
    "Content-Type":    "application/json",
    "Accept":          "application/json",
    "X-UserType":      "USER",
    "X-SourceID":      "WEB",
    "X-ClientLocalIP": "127.0.0.1",
    "X-ClientPublicIP":"127.0.0.1",
    "X-MACAddress":    "00:00:00:00:00:00",
    "X-PrivateKey":    API_KEY,
}

# NSE index tokens
INDEX_TOKENS = {
    "NIFTY50":    {"token": "99926000", "exch": "NSE", "name": "Nifty 50"},
    "BANKNIFTY":  {"token": "99926009", "exch": "NSE", "name": "Nifty Bank"},
    "FINNIFTY":   {"token": "99926037", "exch": "NSE", "name": "Nifty Fin Service"},
    "MIDCPNIFTY": {"token": "99926074", "exch": "NSE", "name": "Nifty Midcap"},
    "SENSEX":     {"token": "1",        "exch": "BSE", "name": "Sensex"},
    "INDIAVIX":   {"token": "99919000", "exch": "NSE", "name": "India VIX"},
}

# NSE stock tokens for top movers
STOCK_TOKENS = {
    "RELIANCE":   "2885",  "TCS":        "11536", "HDFCBANK":   "1333",
    "INFY":       "1594",  "ICICIBANK":  "4963",  "WIPRO":      "3787",
    "AXISBANK":   "5900",  "KOTAKBANK":  "1922",  "LT":         "11483",
    "SBIN":       "3045",  "BAJFINANCE": "317",   "MARUTI":     "10999",
    "TITAN":      "3506",  "SUNPHARMA":  "3351",  "HCLTECH":    "7229",
    "BHARTIARTL": "10604", "ITC":        "1660",  "ASIANPAINT": "236",
    "ADANIENT":   "25",    "HINDUNILVR": "1394",
}


# ── AUTH ────────────────────────────────────────────────────────────────────
def login() -> str:
    totp = pyotp.TOTP(TOTP_SECRET).now()
    r = requests.post(
        f"{BASE_URL}/rest/auth/angelbroking/user/v1/loginByPassword",
        headers=HEADERS_BASE,
        json={"clientcode": CLIENT_CODE, "password": MPIN, "totp": totp},
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("status") or not data.get("data", {}).get("jwtToken"):
        raise RuntimeError(f"Login failed: {data.get('message', 'unknown')}")
    print(f"✅ Logged in as {CLIENT_CODE}")
    return data["data"]["jwtToken"]


# ── MARKET DATA ─────────────────────────────────────────────────────────────
def get_market_data(jwt: str, exchange_tokens: dict) -> list:
    headers = {**HEADERS_BASE, "Authorization": f"Bearer {jwt}"}
    r = requests.post(
        f"{BASE_URL}/rest/secure/angelbroking/market/v1/getMarketData",
        headers=headers,
        json={"mode": "FULL", "exchangeTokens": exchange_tokens},
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    return data.get("data", {}).get("fetched", [])


# ── OPTION CHAIN ─────────────────────────────────────────────────────────────
def get_option_chain(jwt: str, symbol: str = "NIFTY") -> dict | None:
    headers = {**HEADERS_BASE, "Authorization": f"Bearer {jwt}"}
    try:
        r = requests.get(
            f"{BASE_URL}/rest/secure/angelbroking/derivatives/v1/getCandleData",
            headers=headers,
            params={"name": symbol, "expirydate": ""},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get("status"):
            return None
        return data.get("data")
    except Exception as e:
        print(f"⚠ Option chain error: {e}")
        return None


# ── PROCESS DATA ─────────────────────────────────────────────────────────────
def build_output(jwt: str) -> dict:
    now_utc = datetime.now(timezone.utc)

    # ─ Indices ─────────────────────────────────────────────────────────────
    nse_toks = [t["token"] for t in INDEX_TOKENS.values() if t["exch"] == "NSE"]
    bse_toks = [t["token"] for t in INDEX_TOKENS.values() if t["exch"] == "BSE"]
    raw = get_market_data(jwt, {"NSE": nse_toks, "BSE": bse_toks})

    # Build token→symbol lookup
    tok_to_sym = {v["token"]: k for k, v in INDEX_TOKENS.items()}
    tok_to_exch = {v["token"]: v["exch"] for k, v in INDEX_TOKENS.items()}

    indices = {}
    for item in raw:
        tok  = item.get("symbolToken") or item.get("token", "")
        sym  = tok_to_sym.get(tok)
        if not sym:
            continue
        ltp  = float(item.get("ltp", 0))
        close = float(item.get("close", 0) or item.get("previousClose", 0) or ltp)
        chg  = round((ltp - close) / close * 100, 2) if close else 0.0
        indices[sym] = {
            "ltp":   ltp,
            "chg":   chg,
            "open":  float(item.get("open", 0)),
            "high":  float(item.get("high", 0)),
            "low":   float(item.get("low", 0)),
            "close": close,
            "name":  INDEX_TOKENS[sym]["name"],
        }
    print(f"📊 Indices fetched: {list(indices.keys())}")

    # ─ Stocks / Movers ────────────────────────────────────────────────────
    stock_raw = get_market_data(jwt, {"NSE": list(STOCK_TOKENS.values())})
    tok_to_stock = {v: k for k, v in STOCK_TOKENS.items()}

    stocks = []
    for item in stock_raw:
        tok  = item.get("symbolToken") or item.get("token", "")
        sym  = tok_to_stock.get(tok)
        if not sym:
            continue
        ltp   = float(item.get("ltp", 0))
        close = float(item.get("close", 0) or item.get("previousClose", 0) or ltp)
        chg   = round((ltp - close) / close * 100, 2) if close else 0.0
        stocks.append({"symbol": sym, "ltp": ltp, "chg": chg})

    gainers = sorted([s for s in stocks if s["chg"] > 0], key=lambda x: -x["chg"])[:10]
    losers  = sorted([s for s in stocks if s["chg"] < 0], key=lambda x:  x["chg"])[:10]
    print(f"📈 Stocks fetched: {len(stocks)} — {len(gainers)} gainers, {len(losers)} losers")

    # ─ Option Chain ───────────────────────────────────────────────────────
    fo_summary = None
    chain_data = get_option_chain(jwt, "NIFTY")
    if chain_data:
        try:
            spot       = float(chain_data.get("underlyingValue", 0))
            chain_rows = chain_data.get("optionChainData", [])
            strikes    = []
            for row in chain_rows:
                ce = row.get("CE", {})
                pe = row.get("PE", {})
                sp = float(row.get("strikePrice", 0))
                strikes.append({
                    "strike":  sp,
                    "atm":     abs(sp - spot) < 51,
                    "callOI":  int(ce.get("openInterest", 0)),
                    "callLTP": float(ce.get("lastPrice", 0)),
                    "putOI":   int(pe.get("openInterest", 0)),
                    "putLTP":  float(pe.get("lastPrice", 0)),
                })
            total_call = sum(s["callOI"] for s in strikes) or 1
            total_put  = sum(s["putOI"]  for s in strikes)
            pcr        = round(total_put / total_call, 2)

            def pain(sp):
                c = sum(max(0, sp - s["strike"]) * s["callOI"] for s in strikes)
                p = sum(max(0, s["strike"] - sp) * s["putOI"]  for s in strikes)
                return c + p

            maxpain = min(strikes, key=lambda s: pain(s["strike"]))["strike"] if strikes else 0
            fo_summary = {
                "symbol":   "NIFTY",
                "spot":     spot,
                "pcr":      pcr,
                "maxpain":  maxpain,
                "totaloi":  total_call + total_put,
                "chain":    strikes[:40],   # limit payload — ATM ±20 strikes
            }
            print(f"📉 F&O: spot={spot}, PCR={pcr}, MaxPain={maxpain}")
        except Exception as e:
            print(f"⚠ F&O parse error: {e}")

    return {
        "timestamp": now_utc.isoformat(),
        "source":    "GitHub Actions + Angel One SmartAPI",
        "market":    "NSE/BSE",
        "indices":   indices,
        "movers":    {"gainers": gainers, "losers": losers},
        "fo":        fo_summary,
    }


# ── MAIN ────────────────────────────────────────────────────────────────────
def main():
    print(f"🚀 fetch_market.py starting — {datetime.now(timezone.utc).isoformat()}")

    # Skip outside market hours (extra safety — workflow schedule already handles this)
    now_ist_hour   = (datetime.now(timezone.utc).hour + 5) % 24
    now_ist_minute = datetime.now(timezone.utc).minute
    ist_minutes    = now_ist_hour * 60 + now_ist_minute
    market_open    = 9 * 60 + 15   # 9:15 AM
    market_close   = 15 * 60 + 30  # 3:30 PM

    if not (market_open <= ist_minutes <= market_close):
        print(f"⏸  Outside market hours (IST {now_ist_hour:02d}:{now_ist_minute:02d}) — writing stale marker")
        # Write a status-only file so the journal knows market is closed
        try:
            existing = json.load(open("data.json"))
        except Exception:
            existing = {}
        existing["market_status"] = "closed"
        existing["timestamp"]     = datetime.now(timezone.utc).isoformat()
        json.dump(existing, open("data.json", "w"), indent=2)
        print("✅ data.json updated with closed status")
        return

    jwt = login()
    output = build_output(jwt)
    output["market_status"] = "open"

    json.dump(output, open("data.json", "w"), indent=2)
    print(f"✅ data.json written — {len(str(output))} bytes")
    print(f"   Indices: {list(output['indices'].keys())}")
    print(f"   Movers:  {len(output['movers']['gainers'])} gainers, {len(output['movers']['losers'])} losers")
    print(f"   F&O:     {'yes' if output['fo'] else 'no'}")


if __name__ == "__main__":
    main()
