import os as _early_os
_early_os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
_early_os.environ.setdefault("GRPC_LOG_SEVERITY_LEVEL", "ERROR")
_early_os.environ.setdefault("GLOG_minloglevel", "2")
_early_os.environ.setdefault("ABSL_LOG_SEVERITY", "2")
_early_os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
_early_os.environ.setdefault("ABSL_LOGGING_STDERR_THRESHOLD", "3")
_early_os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")

import logging, os, sys, json, argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from functools import lru_cache
from contextlib import contextmanager

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

try:
    from absl import logging as absl_logging
    absl_logging.set_verbosity(absl_logging.ERROR)
except Exception:
    pass

import google.generativeai as genai

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
log = logging.getLogger("txsec")

@contextmanager
def log_section(title: str):
    log.info("%s ...", title)
    try:
        yield
        log.info("%s ...done", title)
    except Exception:
        log.exception("%s ...failed", title)
        raise

load_dotenv()
ETH_RPC_URL    = os.getenv("ETH_RPC_URL", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "").strip() or "gemini-2.5-flash"

if not ETH_RPC_URL:
    raise RuntimeError("ETH_RPC_URL is not set (.env or environment).")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set (.env or environment).")

genai.configure(api_key=GEMINI_API_KEY)
log.info("Config → ETH_RPC_URL set: %s | GEMINI_MODEL: %s", bool(ETH_RPC_URL), GEMINI_MODEL)

def rpc(method: str, params: List[Any]) -> Dict[str, Any]:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    try:
        r = requests.post(ETH_RPC_URL, json=payload, timeout=50)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        raise RuntimeError(f"RPC network error: {e}")
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data.get("result")

def to_address(topic32: str) -> Optional[str]:
    if not isinstance(topic32, str) or not topic32.startswith("0x") or len(topic32) < 42:
        return None
    return "0x" + topic32[-40:].lower()

def hex_to_int_str(hexval: Optional[str]) -> str:
    if not isinstance(hexval, str):
        return "0"
    try:
        return str(int(hexval, 16))
    except Exception:
        return "0"

def safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default

app = FastAPI(title="Tx Risk Triage (Steps 1–6)", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

def _eth_call(to: str, data: str) -> Optional[str]:
    try:
        res = rpc("eth_call", [{"to": to, "data": data}, "latest"])
        return res if isinstance(res, str) and res.startswith("0x") else None
    except Exception:
        return None

def _decode_uint256(hexdata: Optional[str]) -> Optional[int]:
    try:
        return int(hexdata, 16) if hexdata else None
    except Exception:
        return None

def _decode_string_or_bytes32(hexdata: Optional[str]) -> Optional[str]:
    if not isinstance(hexdata, str) or not hexdata.startswith("0x") or len(hexdata) <= 2:
        return None
    try:
        raw = bytes.fromhex(hexdata[2:])
        if len(raw) >= 64:
            offset = int.from_bytes(raw[0:32], "big")
            if offset == 32:
                length = int.from_bytes(raw[32:64], "big")
                if 64 + length <= len(raw):
                    return raw[64:64+length].decode("utf-8", "ignore").rstrip("\x00")
        return raw[:32].rstrip(b"\x00").decode("ascii", "ignore")
    except Exception:
        return None

@lru_cache(maxsize=2048)
def get_erc20_metadata(token_address: str) -> Dict[str, Optional[Any]]:
    addr = (token_address or "").lower()
    symbol_hex   = _eth_call(addr, "0x95d89b41")
    decimals_hex = _eth_call(addr, "0x313ce567")
    sym = _decode_string_or_bytes32(symbol_hex)
    if isinstance(sym, str):
        sym = sym.replace("\x00", "")
    return {"symbol": sym, "decimals": _decode_uint256(decimals_hex)}

if __name__ == "__main__":
    print("[health]", {"status": "ok"})
    try:
        print("[rpc] eth_blockNumber →", rpc("eth_blockNumber", []))
    except Exception as e:
        print("[rpc] failed:", e)
    usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    try:
        print("[erc20]", get_erc20_metadata(usdc))
    except Exception as e:
        print("[erc20] failed:", e)
