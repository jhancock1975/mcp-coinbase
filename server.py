import os
import hmac
import hashlib
import time
from typing import Any, Dict

import requests
from fastapi import FastAPI, HTTPException

API_URL = "https://api.coinbase.com/v2"

COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")
COINBASE_API_SECRET = os.getenv("COINBASE_API_SECRET")

if not COINBASE_API_KEY or not COINBASE_API_SECRET:
    print("WARNING: COINBASE_API_KEY or COINBASE_API_SECRET not set.")

app = FastAPI(
    title="Coinbase MCP Server",
    description="Minimal Coinbase MCP-compatible server for balances and accounts.",
    version="1.0.0",
)

def coinbase_request(method: str, path: str, params: Dict[str, Any] | None = None):
    if not COINBASE_API_KEY or not COINBASE_API_SECRET:
        raise HTTPException(status_code=500, detail="Coinbase API credentials are not configured.")

    timestamp = str(int(time.time()))
    request_path = path
    if params:
        from urllib.parse import urlencode
        query = urlencode(params)
        request_path = f"{path}?{query}"

    message = timestamp + method.upper() + request_path
    signature = hmac.new(
        COINBASE_API_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "CB-ACCESS-KEY": COINBASE_API_KEY,
        "CB-ACCESS-SIGN": signature,
        "CB-ACCESS-TIMESTAMP": timestamp,
        "CB-VERSION": "2023-01-01",
    }

    url = API_URL + request_path
    resp = requests.request(method.upper(), url, headers=headers)

    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=f"Coinbase API error: {resp.text}")

    return resp.json()

@app.get("/health")
def health():
    return {
        "status": "ok",
        "coinbase_configured": bool(COINBASE_API_KEY and COINBASE_API_SECRET),
    }

@app.get("/accounts")
def list_accounts():
    return coinbase_request("GET", "/accounts")

@app.get("/balances")
def balances():
    data = coinbase_request("GET", "/accounts")
    accounts = data.get("data", [])
    simplified = []
    for acc in accounts:
        balance = acc.get("balance", {})
        amount = balance.get("amount")
        currency = balance.get("currency")
        if amount is None or currency is None:
            continue
        simplified.append({
            "name": acc.get("name"),
            "currency": currency,
            "amount": amount,
            "type": acc.get("type"),
            "primary": acc.get("primary", False),
        })
    return {"balances": simplified}
