import os
import time
import secrets
import json
import asyncio
import hashlib
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse

import requests
from fastapi import FastAPI, HTTPException, Header, Request, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, RedirectResponse, HTMLResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import jwt

# Advanced Trade API base URL
API_URL = "https://api.coinbase.com/api/v3/brokerage"

COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")
COINBASE_API_SECRET = os.getenv("COINBASE_API_SECRET")
# Optional API key for ChatGPT authentication (simple auth)
CHATGPT_API_KEY = os.getenv("CHATGPT_API_KEY")

# OAuth2 Configuration
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "coinbase-mcp-client")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", secrets.token_urlsafe(32))
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://mcp.taptupo.com/oauth/callback")

# In-memory storage for OAuth (use Redis/DB in production)
oauth_codes: Dict[str, Dict] = {}  # authorization_code -> {client_id, redirect_uri, expires}
oauth_tokens: Dict[str, Dict] = {}  # access_token -> {client_id, expires, scope}

if not COINBASE_API_KEY or not COINBASE_API_SECRET:
    print("WARNING: COINBASE_API_KEY or COINBASE_API_SECRET not set.")

print(f"OAuth Client ID: {OAUTH_CLIENT_ID}")
print(f"OAuth Client Secret: {OAUTH_CLIENT_SECRET[:8]}...")  # Only print first 8 chars

# Response models for OpenAPI schema
class HealthResponse(BaseModel):
    status: str
    coinbase_configured: bool

app = FastAPI(
    title="Coinbase Advanced Trade MCP Server",
    description="A server that provides access to Coinbase Advanced Trade API for trading, orders, and market data. Use this for cryptocurrency trading operations.",
    version="2.0.0",
    servers=[
        {"url": "https://mcp.taptupo.com", "description": "Production server"}
    ],
)

# Add CORS middleware for ChatGPT
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://chat.openai.com", "https://chatgpt.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_api_key(authorization: str = Header(None)):
    """Verify the API key or OAuth token."""
    # If no auth configured at all, allow access
    if not CHATGPT_API_KEY and not OAUTH_CLIENT_SECRET:
        return True
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    # Handle "Bearer <token>" format
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    
    # Check if it's a valid OAuth token
    if token in oauth_tokens:
        token_data = oauth_tokens[token]
        if token_data["expires"] > time.time():
            return True
        else:
            # Token expired, remove it
            del oauth_tokens[token]
            raise HTTPException(status_code=401, detail="Token expired")
    
    # Check if it matches the simple API key
    if CHATGPT_API_KEY and token == CHATGPT_API_KEY:
        return True
    
    raise HTTPException(status_code=401, detail="Invalid token")


def build_jwt(method: str, uri: str) -> str:
    """Build a JWT token for CDP API authentication."""
    if not COINBASE_API_KEY or not COINBASE_API_SECRET:
        raise HTTPException(status_code=500, detail="Coinbase API credentials are not configured.")

    # Parse the URI to get host and path
    parsed = urlparse(uri)
    uri_for_jwt = f"{method.upper()} {parsed.netloc}{parsed.path}"

    # Handle the EC private key - replace escaped newlines with actual newlines
    private_key_pem = COINBASE_API_SECRET.replace("\\n", "\n")
    
    # Ensure proper PEM format
    if not private_key_pem.startswith("-----BEGIN EC PRIVATE KEY-----"):
        private_key_pem = f"-----BEGIN EC PRIVATE KEY-----\n{private_key_pem}\n-----END EC PRIVATE KEY-----"

    # Load the EC private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    # Build JWT payload
    now = int(time.time())
    payload = {
        "sub": COINBASE_API_KEY,
        "iss": "cdp",
        "nbf": now,
        "exp": now + 120,  # Token valid for 2 minutes
        "uri": uri_for_jwt,
    }

    # Add nonce for extra security
    payload["nonce"] = secrets.token_hex(16)

    # Sign the JWT with ES256, include kid in header
    headers = {
        "kid": COINBASE_API_KEY,
        "typ": "JWT",
        "alg": "ES256",
        "nonce": secrets.token_hex(16),
    }
    token = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
    return token


def coinbase_request(method: str, path: str, params: Dict[str, Any] | None = None):
    """Make a request to Coinbase Advanced Trade API."""
    if not COINBASE_API_KEY or not COINBASE_API_SECRET:
        raise HTTPException(status_code=500, detail="Coinbase API credentials are not configured.")

    request_path = path
    if params:
        query = urlencode(params)
        request_path = f"{path}?{query}"

    url = API_URL + request_path
    
    # Build JWT for CDP authentication
    token = build_jwt(method, url)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    resp = requests.request(method.upper(), url, headers=headers)

    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=f"Coinbase API error: {resp.text}\n")

    return resp.json()


def coinbase_request_with_body(method: str, path: str, body: Dict[str, Any]):
    """Make a Coinbase API request with a JSON body (for POST/PUT requests)."""
    if not COINBASE_API_KEY or not COINBASE_API_SECRET:
        raise HTTPException(status_code=500, detail="Coinbase API credentials are not configured.")

    url = API_URL + path
    
    # Build JWT for CDP authentication
    token = build_jwt(method, url)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    resp = requests.request(method.upper(), url, headers=headers, json=body)

    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=f"Coinbase API error: {resp.text}\n")

    return resp.json()


@app.get("/health", response_model=HealthResponse, summary="Health Check", description="Check if the server is running and Coinbase is configured")
def health():
    return {
        "status": "ok",
        "coinbase_configured": bool(COINBASE_API_KEY and COINBASE_API_SECRET),
    }


# ============================================
# OAuth2 Endpoints
# ============================================

@app.get("/oauth/authorize", summary="OAuth2 Authorization", description="OAuth2 authorization endpoint for user consent")
async def oauth_authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read"),
    state: str = Query(None)
):
    """OAuth2 authorization endpoint - displays consent page and redirects with auth code."""
    
    # Validate client_id
    if client_id != OAUTH_CLIENT_ID:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    
    # Store the authorization code (expires in 10 minutes)
    oauth_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "expires": time.time() + 600  # 10 minutes
    }
    
    # Build redirect URL with authorization code
    redirect_params = {"code": auth_code}
    if state:
        redirect_params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
    
    # Return a simple HTML page that auto-redirects (simulating user consent)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Coinbase Advanced Trade - Authorization</title>
        <meta http-equiv="refresh" content="0;url={redirect_url}">
        <style>
            body {{ font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }}
            .container {{ text-align: center; padding: 40px; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #0052FF; }}
            p {{ color: #666; }}
            a {{ color: #0052FF; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Coinbase Advanced Trade</h1>
            <p>Authorization granted. Redirecting...</p>
            <p>If not redirected, <a href="{redirect_url}">click here</a>.</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.post("/oauth/token", summary="OAuth2 Token", description="OAuth2 token endpoint to exchange auth code for access token")
async def oauth_token(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    refresh_token: str = Form(None)
):
    """OAuth2 token endpoint - exchanges authorization code for access token."""
    
    # Validate client credentials
    if client_id != OAUTH_CLIENT_ID or client_secret != OAUTH_CLIENT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="Authorization code required")
        
        # Validate authorization code
        if code not in oauth_codes:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        code_data = oauth_codes[code]
        
        # Check expiration
        if code_data["expires"] < time.time():
            del oauth_codes[code]
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Validate redirect_uri matches
        if redirect_uri and redirect_uri != code_data["redirect_uri"]:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")
        
        # Delete the used authorization code
        del oauth_codes[code]
        
        # Generate access token and refresh token
        access_token = secrets.token_urlsafe(32)
        new_refresh_token = secrets.token_urlsafe(32)
        
        # Store access token (expires in 1 hour)
        oauth_tokens[access_token] = {
            "client_id": client_id,
            "expires": time.time() + 3600,  # 1 hour
            "scope": code_data["scope"],
            "refresh_token": new_refresh_token
        }
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": new_refresh_token,
            "scope": code_data["scope"]
        }
    
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token required")
        
        # Find the token with this refresh token
        old_access_token = None
        old_token_data = None
        for token, data in oauth_tokens.items():
            if data.get("refresh_token") == refresh_token:
                old_access_token = token
                old_token_data = data
                break
        
        if not old_token_data:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        
        # Delete old token
        if old_access_token:
            del oauth_tokens[old_access_token]
        
        # Generate new tokens
        access_token = secrets.token_urlsafe(32)
        new_refresh_token = secrets.token_urlsafe(32)
        
        # Store new access token
        oauth_tokens[access_token] = {
            "client_id": client_id,
            "expires": time.time() + 3600,
            "scope": old_token_data["scope"],
            "refresh_token": new_refresh_token
        }
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": new_refresh_token,
            "scope": old_token_data["scope"]
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


@app.get("/oauth/callback", summary="OAuth2 Callback", description="OAuth2 callback endpoint (for testing)")
async def oauth_callback(code: str = Query(None), state: str = Query(None), error: str = Query(None)):
    """OAuth2 callback endpoint - used for testing the OAuth flow."""
    if error:
        return {"error": error}
    return {"message": "Authorization successful", "code": code, "state": state}


@app.get("/.well-known/openid-configuration", summary="OpenID Configuration", description="OpenID Connect discovery document")
async def openid_configuration():
    """OpenID Connect discovery endpoint."""
    base_url = "https://mcp.taptupo.com"
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "scopes_supported": ["read", "write", "trade"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"]
    }


# Alias routes for /authorize and /token (without /oauth prefix)
@app.get("/authorize", summary="OAuth2 Authorization (alias)", include_in_schema=False)
async def authorize_alias(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read"),
    state: str = Query(None)
):
    """Alias for /oauth/authorize."""
    return await oauth_authorize(response_type, client_id, redirect_uri, scope, state)


@app.post("/token", summary="OAuth2 Token (alias)", include_in_schema=False)
async def token_alias(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    refresh_token: str = Form(None)
):
    """Alias for /oauth/token."""
    return await oauth_token(grant_type, code, redirect_uri, client_id, client_secret, refresh_token)


# ============================================
# MCP (Model Context Protocol) Implementation
# ============================================

# MCP Tool definitions for Advanced Trade API
MCP_TOOLS = [
    # ============================================
    # Account Tools
    # ============================================
    {
        "name": "list_accounts",
        "description": "List all trading accounts with balances, holds, and available funds. Returns account UUID, currency, available balance, and hold amounts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of accounts to return (default 49, max 250)"
                },
                "cursor": {
                    "type": "string",
                    "description": "Pagination cursor for fetching next page"
                }
            },
            "required": []
        }
    },
    {
        "name": "get_account",
        "description": "Get details for a specific trading account by UUID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {
                    "type": "string",
                    "description": "The account UUID to retrieve"
                }
            },
            "required": ["account_id"]
        }
    },
    # ============================================
    # Product/Market Data Tools
    # ============================================
    {
        "name": "list_products",
        "description": "List all available trading products/pairs (e.g., BTC-USD, ETH-USD). Returns product IDs, base/quote currencies, trading status, and price info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_type": {
                    "type": "string",
                    "description": "Filter by product type: SPOT, FUTURE",
                    "enum": ["SPOT", "FUTURE"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of products to return"
                }
            },
            "required": []
        }
    },
    {
        "name": "get_product",
        "description": "Get detailed information about a specific trading product including current price, 24h stats, and trading parameters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "The product ID (e.g., 'BTC-USD', 'ETH-USD')"
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "get_product_candles",
        "description": "Get historical OHLCV (Open, High, Low, Close, Volume) candlestick data for a product. Useful for technical analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "The product ID (e.g., 'BTC-USD')"
                },
                "start": {
                    "type": "string",
                    "description": "Start time in Unix timestamp seconds"
                },
                "end": {
                    "type": "string",
                    "description": "End time in Unix timestamp seconds"
                },
                "granularity": {
                    "type": "string",
                    "description": "Candle granularity: ONE_MINUTE, FIVE_MINUTE, FIFTEEN_MINUTE, THIRTY_MINUTE, ONE_HOUR, TWO_HOUR, SIX_HOUR, ONE_DAY",
                    "enum": ["ONE_MINUTE", "FIVE_MINUTE", "FIFTEEN_MINUTE", "THIRTY_MINUTE", "ONE_HOUR", "TWO_HOUR", "SIX_HOUR", "ONE_DAY"]
                }
            },
            "required": ["product_id", "start", "end", "granularity"]
        }
    },
    {
        "name": "get_market_trades",
        "description": "Get recent trades for a product. Shows trade price, size, time, and side (buy/sell).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "The product ID (e.g., 'BTC-USD')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of trades to return (max 1000)"
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "get_best_bid_ask",
        "description": "Get the best bid and ask prices for one or more products. Essential for understanding current market spread.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of product IDs (e.g., ['BTC-USD', 'ETH-USD'])"
                }
            },
            "required": []
        }
    },
    {
        "name": "get_product_book",
        "description": "Get the order book (bids and asks) for a product. Shows market depth at different price levels.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "The product ID (e.g., 'BTC-USD')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of price levels to return on each side"
                }
            },
            "required": ["product_id"]
        }
    },
    # ============================================
    # Order Tools
    # ============================================
    {
        "name": "create_order",
        "description": "Create a new order to buy or sell cryptocurrency. Supports market orders, limit orders, stop orders, and more. WARNING: This will execute real trades!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "The product to trade (e.g., 'BTC-USD')"
                },
                "side": {
                    "type": "string",
                    "description": "Order side: BUY or SELL",
                    "enum": ["BUY", "SELL"]
                },
                "order_type": {
                    "type": "string",
                    "description": "Order type: MARKET, LIMIT, STOP_LIMIT, TRIGGER_BRACKET",
                    "enum": ["MARKET", "LIMIT", "STOP_LIMIT", "TRIGGER_BRACKET"]
                },
                "size": {
                    "type": "string",
                    "description": "Amount of base currency to buy/sell (e.g., '0.01' for 0.01 BTC)"
                },
                "quote_size": {
                    "type": "string",
                    "description": "Amount of quote currency to spend (for market buys, e.g., '100' for $100)"
                },
                "limit_price": {
                    "type": "string",
                    "description": "Limit price for limit orders"
                },
                "stop_price": {
                    "type": "string",
                    "description": "Stop/trigger price for stop orders"
                },
                "time_in_force": {
                    "type": "string",
                    "description": "How long order stays active: GTC (good til cancelled), GTD (good til date), IOC (immediate or cancel), FOK (fill or kill)",
                    "enum": ["GTC", "GTD", "IOC", "FOK"]
                },
                "post_only": {
                    "type": "boolean",
                    "description": "If true, order will only be placed if it would be a maker order (adds liquidity)"
                }
            },
            "required": ["product_id", "side"]
        }
    },
    {
        "name": "preview_order",
        "description": "Preview an order to see estimated fees, slippage, and execution details WITHOUT actually placing the order. Use this before create_order.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "The product to trade (e.g., 'BTC-USD')"
                },
                "side": {
                    "type": "string",
                    "description": "Order side: BUY or SELL",
                    "enum": ["BUY", "SELL"]
                },
                "order_type": {
                    "type": "string",
                    "description": "Order type: MARKET, LIMIT",
                    "enum": ["MARKET", "LIMIT"]
                },
                "size": {
                    "type": "string",
                    "description": "Amount of base currency"
                },
                "quote_size": {
                    "type": "string",
                    "description": "Amount of quote currency"
                },
                "limit_price": {
                    "type": "string",
                    "description": "Limit price for limit orders"
                }
            },
            "required": ["product_id", "side"]
        }
    },
    {
        "name": "list_orders",
        "description": "List historical orders with optional filters. Shows order status, fills, and execution details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "string",
                    "description": "Filter by product ID"
                },
                "order_status": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by status: OPEN, PENDING, FILLED, CANCELLED, EXPIRED, FAILED"
                },
                "order_type": {
                    "type": "string",
                    "description": "Filter by order type: MARKET, LIMIT, STOP_LIMIT"
                },
                "side": {
                    "type": "string",
                    "description": "Filter by side: BUY, SELL"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of orders to return"
                }
            },
            "required": []
        }
    },
    {
        "name": "get_order",
        "description": "Get details of a specific order by order ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "description": "The order ID (UUID)"
                }
            },
            "required": ["order_id"]
        }
    },
    {
        "name": "cancel_orders",
        "description": "Cancel one or more orders by order ID. WARNING: This will cancel real orders!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of order IDs to cancel"
                }
            },
            "required": ["order_ids"]
        }
    },
    {
        "name": "list_fills",
        "description": "List order fills (executed trades). Shows execution price, size, fees, and settlement details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "description": "Filter by order ID"
                },
                "product_id": {
                    "type": "string",
                    "description": "Filter by product ID"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of fills to return"
                }
            },
            "required": []
        }
    },
    # ============================================
    # Portfolio Tools
    # ============================================
    {
        "name": "list_portfolios",
        "description": "List all portfolios. Portfolios allow you to organize your trading into separate groups.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "portfolio_type": {
                    "type": "string",
                    "description": "Filter by type: DEFAULT, CONSUMER, INTX"
                }
            },
            "required": []
        }
    },
    {
        "name": "get_portfolio_breakdown",
        "description": "Get detailed breakdown of a portfolio including positions, allocations, and performance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "portfolio_id": {
                    "type": "string",
                    "description": "The portfolio UUID"
                }
            },
            "required": ["portfolio_id"]
        }
    },
    # ============================================
    # Convert Tools
    # ============================================
    {
        "name": "create_convert_quote",
        "description": "Get a quote to convert one cryptocurrency to another (e.g., BTC to ETH). Returns a trade_id to commit the conversion.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {
                    "type": "string",
                    "description": "Source account UUID"
                },
                "to_account": {
                    "type": "string",
                    "description": "Destination account UUID"
                },
                "amount": {
                    "type": "string",
                    "description": "Amount to convert"
                }
            },
            "required": ["from_account", "to_account", "amount"]
        }
    },
    {
        "name": "commit_convert_trade",
        "description": "Commit/execute a conversion trade using the trade_id from create_convert_quote. WARNING: This executes the conversion!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "trade_id": {
                    "type": "string",
                    "description": "The trade ID from create_convert_quote"
                },
                "from_account": {
                    "type": "string",
                    "description": "Source account UUID"
                },
                "to_account": {
                    "type": "string",
                    "description": "Destination account UUID"
                }
            },
            "required": ["trade_id", "from_account", "to_account"]
        }
    },
    {
        "name": "get_convert_trade",
        "description": "Get details of a conversion trade.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "trade_id": {
                    "type": "string",
                    "description": "The trade ID"
                },
                "from_account": {
                    "type": "string",
                    "description": "Source account UUID"
                },
                "to_account": {
                    "type": "string",
                    "description": "Destination account UUID"
                }
            },
            "required": ["trade_id", "from_account", "to_account"]
        }
    },
    # ============================================
    # Transaction Summary Tool
    # ============================================
    {
        "name": "get_transaction_summary",
        "description": "Get a summary of trading fees, volume, and transaction history over a time period.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "start_date": {
                    "type": "string",
                    "description": "Start date in YYYY-MM-DD format"
                },
                "end_date": {
                    "type": "string",
                    "description": "End date in YYYY-MM-DD format"
                },
                "product_type": {
                    "type": "string",
                    "description": "Filter by product type: SPOT, FUTURE"
                }
            },
            "required": []
        }
    },
    # ============================================
    # Payment Methods Tool
    # ============================================
    {
        "name": "list_payment_methods",
        "description": "List available payment methods (bank accounts, cards, etc.) for deposits and withdrawals.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    # ============================================
    # Server Time Tool
    # ============================================
    {
        "name": "get_server_time",
        "description": "Get the current Coinbase server time. Useful for synchronizing timestamps.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    # ============================================
    # API Key Permissions Tool
    # ============================================
    {
        "name": "get_api_key_permissions",
        "description": "Get the permissions associated with the current API key.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]


def handle_mcp_request(request_data: dict) -> dict:
    """Handle MCP JSON-RPC requests."""
    method = request_data.get("method", "")
    params = request_data.get("params", {})
    request_id = request_data.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "coinbase-advanced-trade-mcp",
                    "version": "2.0.0"
                }
            }
        }
    
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": MCP_TOOLS
            }
        }
    
    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        
        try:
            result = execute_tool(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2)
                        }
                    ]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": str(e)
                }
            }
    
    elif method == "notifications/initialized":
        # This is a notification, no response needed
        return None
    
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }


def execute_tool(tool_name: str, args: dict) -> Any:
    """Execute an MCP tool and return the result."""
    
    # ============================================
    # Account Tools
    # ============================================
    if tool_name == "list_accounts":
        params = {}
        if args.get("limit"):
            params["limit"] = args["limit"]
        if args.get("cursor"):
            params["cursor"] = args["cursor"]
        return coinbase_request("GET", "/accounts", params if params else None)
    
    elif tool_name == "get_account":
        account_id = args.get("account_id")
        if not account_id:
            raise ValueError("account_id is required")
        return coinbase_request("GET", f"/accounts/{account_id}")
    
    # ============================================
    # Product/Market Data Tools
    # ============================================
    elif tool_name == "list_products":
        params = {}
        if args.get("product_type"):
            params["product_type"] = args["product_type"]
        if args.get("limit"):
            params["limit"] = args["limit"]
        return coinbase_request("GET", "/products", params if params else None)
    
    elif tool_name == "get_product":
        product_id = args.get("product_id")
        if not product_id:
            raise ValueError("product_id is required")
        return coinbase_request("GET", f"/products/{product_id}")
    
    elif tool_name == "get_product_candles":
        product_id = args.get("product_id")
        start = args.get("start")
        end = args.get("end")
        granularity = args.get("granularity")
        if not all([product_id, start, end, granularity]):
            raise ValueError("product_id, start, end, and granularity are required")
        params = {"start": start, "end": end, "granularity": granularity}
        return coinbase_request("GET", f"/products/{product_id}/candles", params)
    
    elif tool_name == "get_market_trades":
        product_id = args.get("product_id")
        if not product_id:
            raise ValueError("product_id is required")
        params = {}
        if args.get("limit"):
            params["limit"] = args["limit"]
        return coinbase_request("GET", f"/products/{product_id}/ticker", params if params else None)
    
    elif tool_name == "get_best_bid_ask":
        params = {}
        if args.get("product_ids"):
            params["product_ids"] = ",".join(args["product_ids"])
        return coinbase_request("GET", "/best_bid_ask", params if params else None)
    
    elif tool_name == "get_product_book":
        product_id = args.get("product_id")
        if not product_id:
            raise ValueError("product_id is required")
        params = {"product_id": product_id}
        if args.get("limit"):
            params["limit"] = args["limit"]
        return coinbase_request("GET", "/product_book", params)
    
    # ============================================
    # Order Tools
    # ============================================
    elif tool_name == "create_order":
        product_id = args.get("product_id")
        side = args.get("side")
        if not product_id or not side:
            raise ValueError("product_id and side are required")
        
        # Build order configuration based on order type
        order_type = args.get("order_type", "MARKET")
        
        body = {
            "client_order_id": secrets.token_urlsafe(16),
            "product_id": product_id,
            "side": side
        }
        
        if order_type == "MARKET":
            order_config = {"market_market_ioc": {}}
            if args.get("quote_size"):
                order_config["market_market_ioc"]["quote_size"] = args["quote_size"]
            elif args.get("size"):
                order_config["market_market_ioc"]["base_size"] = args["size"]
            else:
                raise ValueError("size or quote_size required for market orders")
            body["order_configuration"] = order_config
        
        elif order_type == "LIMIT":
            if not args.get("limit_price") or not args.get("size"):
                raise ValueError("limit_price and size required for limit orders")
            order_config = {
                "limit_limit_gtc": {
                    "base_size": args["size"],
                    "limit_price": args["limit_price"],
                    "post_only": args.get("post_only", False)
                }
            }
            body["order_configuration"] = order_config
        
        elif order_type == "STOP_LIMIT":
            if not all([args.get("limit_price"), args.get("stop_price"), args.get("size")]):
                raise ValueError("limit_price, stop_price, and size required for stop-limit orders")
            order_config = {
                "stop_limit_stop_limit_gtc": {
                    "base_size": args["size"],
                    "limit_price": args["limit_price"],
                    "stop_price": args["stop_price"],
                    "stop_direction": "STOP_DIRECTION_STOP_DOWN" if side == "SELL" else "STOP_DIRECTION_STOP_UP"
                }
            }
            body["order_configuration"] = order_config
        
        return coinbase_request_with_body("POST", "/orders", body)
    
    elif tool_name == "preview_order":
        product_id = args.get("product_id")
        side = args.get("side")
        if not product_id or not side:
            raise ValueError("product_id and side are required")
        
        order_type = args.get("order_type", "MARKET")
        
        body = {
            "product_id": product_id,
            "side": side
        }
        
        if order_type == "MARKET":
            order_config = {"market_market_ioc": {}}
            if args.get("quote_size"):
                order_config["market_market_ioc"]["quote_size"] = args["quote_size"]
            elif args.get("size"):
                order_config["market_market_ioc"]["base_size"] = args["size"]
            body["order_configuration"] = order_config
        
        elif order_type == "LIMIT":
            order_config = {
                "limit_limit_gtc": {
                    "base_size": args.get("size", "0"),
                    "limit_price": args.get("limit_price", "0"),
                    "post_only": False
                }
            }
            body["order_configuration"] = order_config
        
        return coinbase_request_with_body("POST", "/orders/preview", body)
    
    elif tool_name == "list_orders":
        params = {}
        if args.get("product_id"):
            params["product_id"] = args["product_id"]
        if args.get("order_status"):
            params["order_status"] = args["order_status"]
        if args.get("order_type"):
            params["order_type"] = args["order_type"]
        if args.get("side"):
            params["side"] = args["side"]
        if args.get("limit"):
            params["limit"] = args["limit"]
        return coinbase_request("GET", "/orders/historical/batch", params if params else None)
    
    elif tool_name == "get_order":
        order_id = args.get("order_id")
        if not order_id:
            raise ValueError("order_id is required")
        return coinbase_request("GET", f"/orders/historical/{order_id}")
    
    elif tool_name == "cancel_orders":
        order_ids = args.get("order_ids")
        if not order_ids:
            raise ValueError("order_ids is required")
        body = {"order_ids": order_ids}
        return coinbase_request_with_body("POST", "/orders/batch_cancel", body)
    
    elif tool_name == "list_fills":
        params = {}
        if args.get("order_id"):
            params["order_id"] = args["order_id"]
        if args.get("product_id"):
            params["product_id"] = args["product_id"]
        if args.get("limit"):
            params["limit"] = args["limit"]
        return coinbase_request("GET", "/orders/historical/fills", params if params else None)
    
    # ============================================
    # Portfolio Tools
    # ============================================
    elif tool_name == "list_portfolios":
        params = {}
        if args.get("portfolio_type"):
            params["portfolio_type"] = args["portfolio_type"]
        return coinbase_request("GET", "/portfolios", params if params else None)
    
    elif tool_name == "get_portfolio_breakdown":
        portfolio_id = args.get("portfolio_id")
        if not portfolio_id:
            raise ValueError("portfolio_id is required")
        return coinbase_request("GET", f"/portfolios/{portfolio_id}")
    
    # ============================================
    # Convert Tools
    # ============================================
    elif tool_name == "create_convert_quote":
        from_account = args.get("from_account")
        to_account = args.get("to_account")
        amount = args.get("amount")
        if not all([from_account, to_account, amount]):
            raise ValueError("from_account, to_account, and amount are required")
        body = {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount
        }
        return coinbase_request_with_body("POST", "/convert/quote", body)
    
    elif tool_name == "commit_convert_trade":
        trade_id = args.get("trade_id")
        from_account = args.get("from_account")
        to_account = args.get("to_account")
        if not all([trade_id, from_account, to_account]):
            raise ValueError("trade_id, from_account, and to_account are required")
        body = {
            "from_account": from_account,
            "to_account": to_account
        }
        return coinbase_request_with_body("POST", f"/convert/{trade_id}", body)
    
    elif tool_name == "get_convert_trade":
        trade_id = args.get("trade_id")
        from_account = args.get("from_account")
        to_account = args.get("to_account")
        if not all([trade_id, from_account, to_account]):
            raise ValueError("trade_id, from_account, and to_account are required")
        params = {"from_account": from_account, "to_account": to_account}
        return coinbase_request("GET", f"/convert/{trade_id}", params)
    
    # ============================================
    # Transaction Summary Tool
    # ============================================
    elif tool_name == "get_transaction_summary":
        params = {}
        if args.get("start_date"):
            params["start_date"] = args["start_date"]
        if args.get("end_date"):
            params["end_date"] = args["end_date"]
        if args.get("product_type"):
            params["product_type"] = args["product_type"]
        return coinbase_request("GET", "/transaction_summary", params if params else None)
    
    # ============================================
    # Payment Methods Tool
    # ============================================
    elif tool_name == "list_payment_methods":
        return coinbase_request("GET", "/payment_methods")
    
    # ============================================
    # Server Time Tool
    # ============================================
    elif tool_name == "get_server_time":
        return coinbase_request("GET", "/time")
    
    # ============================================
    # API Key Permissions Tool
    # ============================================
    elif tool_name == "get_api_key_permissions":
        return coinbase_request("GET", "/key_permissions")
    
    else:
        raise ValueError(f"Unknown tool: {tool_name}")


@app.get("/sse")
async def sse_endpoint(request: Request):
    """Server-Sent Events endpoint for MCP communication."""
    async def event_generator():
        # Send initial connection event
        yield f"data: {json.dumps({'type': 'connection', 'status': 'connected'})}\n\n"
        
        # Keep connection alive
        while True:
            if await request.is_disconnected():
                break
            # Send heartbeat every 30 seconds
            yield f": heartbeat\n\n"
            await asyncio.sleep(30)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@app.post("/mcp")
async def mcp_endpoint(request: Request, authorization: str = Header(None)):
    """MCP JSON-RPC endpoint."""
    verify_api_key(authorization)
    
    body = await request.json()
    
    # Handle batch requests
    if isinstance(body, list):
        responses = []
        for req in body:
            response = handle_mcp_request(req)
            if response is not None:
                responses.append(response)
        return responses
    
    # Handle single request
    response = handle_mcp_request(body)
    if response is None:
        return {"jsonrpc": "2.0", "result": {}}
    return response


@app.get("/mcp")
async def mcp_info():
    """MCP server information endpoint."""
    return {
        "name": "coinbase-advanced-trade-mcp",
        "version": "2.0.0",
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        }
    }


# ============================================
# REST API Endpoints (for direct access)
# ============================================

@app.get("/accounts", summary="List Accounts", description="List all trading accounts")
def rest_list_accounts(authorization: str = Header(None)):
    verify_api_key(authorization)
    return coinbase_request("GET", "/accounts")


@app.get("/products", summary="List Products", description="List all available trading products")
def rest_list_products(authorization: str = Header(None)):
    verify_api_key(authorization)
    return coinbase_request("GET", "/products")


@app.get("/products/{product_id}", summary="Get Product", description="Get details for a specific product")
def rest_get_product(product_id: str, authorization: str = Header(None)):
    verify_api_key(authorization)
    return coinbase_request("GET", f"/products/{product_id}")
