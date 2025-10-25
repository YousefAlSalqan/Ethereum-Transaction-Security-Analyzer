# app.py
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------------
# Silence gRPC/absl noise (must be set BEFORE importing google/grpc)
# --------------------------------------------------------------------------
import os as _early_os
# Keep gRPC/absl noise down
_early_os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
_early_os.environ.setdefault("GRPC_LOG_SEVERITY_LEVEL", "ERROR")

# Some stacks use glog/absl; move level to WARNING/ERROR
_early_os.environ.setdefault("GLOG_minloglevel", "2")      # 0=INFO,1=WARNING,2=ERROR,3=FATAL
_early_os.environ.setdefault("ABSL_LOG_SEVERITY", "2")     # 0=INFO,1=WARNING,2=ERROR,3=FATAL

# If TF is present in the environment, keep it quiet too
_early_os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")  # 1=WARNING,2=ERROR,3=FATAL
_early_os.environ.setdefault("ABSL_LOGGING_STDERR_THRESHOLD", "3")  # 3=FATAL
_early_os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")

# --------------------------------------------------------------------------
# Standard imports
# --------------------------------------------------------------------------
import logging
import os
import sys
import json
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import defaultdict
from functools import lru_cache
from contextlib import contextmanager

import requests
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Try to downshift absl verbosity (safe if absent)
try:
    from absl import logging as absl_logging
    absl_logging.set_verbosity(absl_logging.ERROR)
except Exception:
    pass

import google.generativeai as genai

# --------------------------------------------------------------------------
# Environment & configuration
# --------------------------------------------------------------------------
load_dotenv()

ETH_RPC_URL    = os.getenv("ETH_RPC_URL", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

if not ETH_RPC_URL:
    raise RuntimeError("ETH_RPC_URL is not set (.env or environment).")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set (.env or environment).")

genai.configure(api_key=GEMINI_API_KEY)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
log = logging.getLogger("txsec")

# Simple section logger (nice start/finish banners in logs)
@contextmanager
def log_section(title: str):
    log.info("%s ...", title)
    try:
        yield
        log.info("%s ...done", title)
    except Exception:
        log.exception("%s ...failed", title)
        raise

# --------------------------------------------------------------------------
# FastAPI
# --------------------------------------------------------------------------
app = FastAPI(title="Tx Risk Triage (Gemini)", version="1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------
# Constants & helpers
# --------------------------------------------------------------------------
TRANSFER_SIG = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL_SIG = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
MAX_UINT256  = int("f" * 64, 16)

# Prompt size control to avoid LLM overflows on very large receipts
MAX_EVENTS_FOR_PROMPT = 120   # total events allowed in prompt
PROMPT_HEAD = 80             # first N events
PROMPT_TAIL = 40              # last  N events

class TxBody(BaseModel):
    tx: str

def rpc(method: str, params: List[Any]) -> Dict[str, Any]:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    try:
        r = requests.post(ETH_RPC_URL, json=payload, timeout=50)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"RPC network error: {e}")
    if "error" in data:
        raise HTTPException(status_code=502, detail=data["error"])
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

# --------------------------------------------------------------------------
# ERC-20 metadata helpers
# --------------------------------------------------------------------------
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
    addr = token_address.lower()
    symbol_hex   = _eth_call(addr, "0x95d89b41")  # symbol()
    decimals_hex = _eth_call(addr, "0x313ce567")  # decimals()
    sym = _decode_string_or_bytes32(symbol_hex)
    if isinstance(sym, str):
        sym = sym.replace("\x00", "")
    return {
        "symbol": sym,
        "decimals": _decode_uint256(decimals_hex),
    }

# --------------------------------------------------------------------------
# Event decoding
# --------------------------------------------------------------------------
def decode_erc20_logs(receipt: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    logs = receipt.get("logs", []) or []
    for lg in logs:
        topics = [str(t).lower() for t in (lg.get("topics") or [])]
        if not topics:
            continue
        t0 = topics[0]
        token = (lg.get("address") or "").lower()
        if not token:
            continue

        meta = get_erc20_metadata(token)
        symbol = meta.get("symbol")
        decimals = meta.get("decimals")

        if t0 == TRANSFER_SIG and len(topics) >= 3:
            ev = {
                "type": "Transfer",
                "contract": token,
                "from": to_address(topics[1]),
                "to": to_address(topics[2]),
                "value": hex_to_int_str(lg.get("data")),
                "logIndex": lg.get("logIndex"),
                "txIndex": lg.get("transactionIndex"),
                "symbol": symbol,
                "decimals": decimals,
            }
            events.append(ev)

        elif t0 == APPROVAL_SIG and len(topics) >= 3:
            value_str = hex_to_int_str(lg.get("data"))
            is_infinite, is_near_infinite = False, False
            try:
                iv = int(value_str)
                is_infinite = iv >= MAX_UINT256
                is_near_infinite = iv >= MAX_UINT256 - 10
            except Exception:
                pass
            ev = {
                "type": "Approval",
                "contract": token,
                "owner": to_address(topics[1]),
                "spender": to_address(topics[2]),
                "value": value_str,
                "is_infinite": is_infinite,
                "is_near_infinite": is_near_infinite,
                "logIndex": lg.get("logIndex"),
                "txIndex": lg.get("transactionIndex"),
                "symbol": symbol,
                "decimals": decimals,
            }
            events.append(ev)

    # derived floats for convenience
    for ev in events:
        try:
            dec = ev.get("decimals")
            if dec is not None:
                ev["value_float"] = int(ev["value"]) / (10 ** int(dec))
        except Exception:
            pass
    return events

# --------------------------------------------------------------------------
# Deterministic prompt helpers
# --------------------------------------------------------------------------
def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _hex_to_int_safe(h: str) -> int:
    try:
        return int(h, 16)
    except Exception:
        return -1

def canonicalize_event(ev: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "type": str(ev.get("type", "")),
        "contract": str(ev.get("contract", "")).lower(),
        "logIndex": str(ev.get("logIndex", "")),
        "txIndex": str(ev.get("txIndex", "")),
    }

    if out["type"] == "Transfer":
        out["from"]  = str(ev.get("from", "")).lower()
        out["to"]    = str(ev.get("to", "")).lower()
        out["value"] = str(ev.get("value", "0"))

    elif out["type"] == "Approval":
        out["owner"]            = str(ev.get("owner", "")).lower()
        out["spender"]          = str(ev.get("spender", "")).lower()
        out["value"]            = str(ev.get("value", "0"))
        out["is_infinite"]      = bool(ev.get("is_infinite", False))
        out["is_near_infinite"] = bool(ev.get("is_near_infinite", False))

    if "decimals" in ev and isinstance(ev["decimals"], int):
        out["decimals"] = ev["decimals"]
    if "symbol" in ev and isinstance(ev["symbol"], str):
        out["symbol"] = ev["symbol"].replace("\x00", "")

    return out

def canonicalize_events(events: List[dict]) -> List[dict]:
    norm = [canonicalize_event(e) for e in events]
    return sorted(norm, key=lambda e: _hex_to_int_safe(e.get("logIndex", "")))

def canonicalize_tx_meta(tx_meta: dict) -> dict:
    return {
        "hash": str(tx_meta.get("hash", "")),
        "from": str(tx_meta.get("from", "")).lower(),
        "to": str(tx_meta.get("to", "")).lower(),
        "blockNumber": str(tx_meta.get("blockNumber", "")),
        "status": str(tx_meta.get("status", "")),
    }

def canonicalize_hints(hints: List[str]) -> List[str]:
    return sorted({h.strip() for h in hints if isinstance(h, str) and h.strip()})

def build_stable_facts(tx_meta: dict, decoded_events: List[dict], hints: Optional[List[str]] = None) -> str:
    # canonicalize first
    norm_events = canonicalize_events(decoded_events)

    truncated = False
    if len(norm_events) > MAX_EVENTS_FOR_PROMPT:
        truncated = True
        head = norm_events[:PROMPT_HEAD]
        tail = norm_events[-PROMPT_TAIL:]
        norm_events = head + tail

    facts = {
        "tx_meta": canonicalize_tx_meta(tx_meta),
        "decoded_events": norm_events,
    }
    if hints:
        facts["heuristic_hints"] = canonicalize_hints(hints)
    if truncated:
        facts["__prompt_note"] = {
            "truncated": True,
            "original_event_count": len(decoded_events),
            "included_event_count": len(norm_events),
            "sampling": f"head:{PROMPT_HEAD}, tail:{PROMPT_TAIL}"
        }

    return canonical_json(facts)

# --------------------------------------------------------------------------
# LLM helpers
# --------------------------------------------------------------------------
def build_llm_prompt(tx_meta: Dict[str, Any], decoded_events: List[Dict[str, Any]], hints: Optional[List[str]]=None) -> str:
    schema_text = (
        'Return ONE JSON object with EXACTLY these keys:\n'
        '{"risk_level":"low|suspicious|high","confidence":<0..1>,'
        '"factors_triggered":["<string>",...],"rationale":"<<=280 chars>"}\n'
        'Rules:\n'
        '- Output MUST be valid JSON (no comments, trailing commas, or markdown).\n'
        '- Use ONLY the keys above (no extra keys, no null values).\n'
        '- If "heuristic_hints" is present and non-empty, include at least one accurate hint in "factors_triggered".\n'
        '- IMPORTANT: Return MINIFIED JSON (no spaces or line breaks).'
    )
    good_example = (
        'Example (GOOD):\n'
        '{"risk_level":"high","confidence":0.92,'
        '"factors_triggered":["infinite approval","known phishing spender"],'
        '"rationale":"MAX_UINT256 approval to 0xabc...; spender has phishing history."}'
    )
    facts_json = build_stable_facts(tx_meta, decoded_events, hints)
    return (
        "You are a blockchain security triage assistant.\n"
        "Be precise, skeptical, and deterministic.\n\n"
        f"{schema_text}\n\n{good_example}\n\n"
        "Now assess the following transaction facts (JSON):\n"
        f"{facts_json}\n\n"
        "Respond with MINIFIED JSON only. No prose. No markdown. No code fences."
    )

def normalize_risk_assessment(raw: Dict[str, Any]) -> Dict[str, Any]:
    result = {"risk_level":"low","confidence":0.5,"factors_triggered":[],"rationale":"No assessment."}
    if not isinstance(raw, dict):
        return result
    rl = str(raw.get("risk_level","low")).lower()
    if rl not in {"low","suspicious","high"}:
        rl="low"
    result["risk_level"]=rl
    try:
        cf=float(raw.get("confidence",0.5)); result["confidence"]=max(0.0,min(1.0,cf))
    except Exception:
        pass
    ft = raw.get("factors_triggered",[])
    if isinstance(ft,list):
        result["factors_triggered"]=[str(x) for x in ft if isinstance(x,(str,int,float))]
    result["rationale"]=str(raw.get("rationale") or "")[:280]
    return result

def heuristic_risk_fallback(tx_meta: Dict[str, Any], events: List[Dict[str, Any]], hints: List[str]) -> Dict[str, Any]:
    high_flags = any("infinite" in (h or "").lower() for h in (hints or []))
    suspicious_flags = any(("fan-out" in (h or "").lower()) or ("multiple approvals" in (h or "").lower())
                           for h in (hints or []))
    if high_flags:
        risk_level, confidence = "high", 0.85
    elif suspicious_flags:
        risk_level, confidence = "suspicious", 0.7
    else:
        risk_level, confidence = "low", 0.6

    rationale_bits = []
    if hints:
        rationale_bits.append("; ".join(hints[:3]))
    if not rationale_bits:
        rationale_bits.append("Heuristic only (LLM unavailable).")

    return {
        "risk_level": risk_level,
        "confidence": confidence,
        "factors_triggered": (hints or [])[:3],
        "rationale": (". ".join(rationale_bits))[:280],
    }

def call_gemini_for_risk(tx_meta: Dict[str, Any],decoded_events: List[Dict[str, Any]],heuristic_hints: Optional[List[str]] = None,) -> Dict[str, Any]:
    prompt_text = build_llm_prompt(tx_meta, decoded_events, heuristic_hints)
    model = genai.GenerativeModel(
        GEMINI_MODEL,
        generation_config={
            "response_mime_type": "application/json",
            "temperature": 0.0,
            "candidate_count": 1,
        },
    )

    # Try a few times with increasing timeouts
    timeouts = [60, 120, 180]  # seconds
    last_err: Optional[Exception] = None
    for t in timeouts:
        try:
            try:
                resp = model.generate_content(prompt_text, request_options={"timeout": t})
            except TypeError:
                # Older SDKs don't support request_options
                resp = model.generate_content(prompt_text)
            content = (resp.text or "").strip()
            parsed: Dict[str, Any] = {}
            try:
                parsed = json.loads(content)
            except Exception:
                start, end = content.find("{"), content.rfind("}")
                if start != -1 and end != -1 and end > start:
                    parsed = json.loads(content[start : end + 1])
            return normalize_risk_assessment(parsed)
        except Exception as e:
            last_err = e
            log.warning("Gemini attempt with timeout=%ss failed: %s", t, e)

    # If all attempts failed, re-raise so our caller can do heuristic fallback
    raise RuntimeError(f"Gemini generate_content failed after retries: {last_err}")

# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------
def aggregate_totals_by_token(events: List[Dict[str, Any]], pov_address: Optional[str]) -> Dict[str, Any]:
    totals: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"in": 0, "out": 0, "symbol": None, "decimals": None}
    )
    pov = (pov_address or "").lower() if pov_address else None

    for ev in events:
        if ev.get("type") != "Transfer":
            continue
        token = ev.get("contract")
        if not token:
            continue
        val = safe_int(ev.get("value"), 0)

        sym = ev.get("symbol")
        if sym and not totals[token]["symbol"]:
            totals[token]["symbol"] = sym
        dec = ev.get("decimals")
        if (dec is not None) and (totals[token]["decimals"] is None):
            totals[token]["decimals"] = dec

        if pov:
            if (ev.get("to") or "").lower() == pov:
                totals[token]["in"] = int(totals[token].get("in", 0) or 0) + val
            elif (ev.get("from") or "").lower() == pov:
                totals[token]["out"] = int(totals[token].get("out", 0) or 0) + val
            else:
                totals[token]["out"] = int(totals[token].get("out", 0) or 0) + val
        else:
            totals[token]["out"] = int(totals[token].get("out", 0) or 0) + val

    out: Dict[str, Any] = {}
    for token, t in totals.items():
        out[token] = {
            "in": str(int(t.get("in", 0) or 0)),
            "out": str(int(t.get("out", 0) or 0)),
            "symbol": t.get("symbol"),
            "decimals": t.get("decimals"),
        }
    return out

def generate_heuristic_hints(events: List[Dict[str, Any]]) -> List[str]:
    hints=[]
    for ev in events:
        if ev.get("type")=="Approval" and ev.get("is_near_infinite"):
            hints.append(f"Near-infinite approval on {ev.get('contract')} to {ev.get('spender')}")
    approvals=[e for e in events if e.get("type")=="Approval"]
    if len(approvals)>1:
        hints.append("Multiple approvals within one transaction")
    tos={e.get("to") for e in events if e.get("type")=="Transfer"}
    if len(tos)>5:
        hints.append("High recipient fan-out (complex routing)")
    return canonicalize_hints(hints)

# --------------------------------------------------------------------------
# Core analysis (reused by API and CLI)
# --------------------------------------------------------------------------
def analyze_tx_core(tx_hash: str) -> Dict[str, Any]:
    """
    Pure function that analyzes a tx hash and returns the full result dict.
    Raises HTTPException on errors.
    """
    with log_section("[1/5] Validate input"):
        if (not isinstance(tx_hash, str)) or (not tx_hash.startswith("0x")) or (len(tx_hash) != 66):
            raise HTTPException(status_code=400, detail="Invalid tx hash")

    with log_section("[2/5] Fetch tx & receipt from RPC"):
        tx_obj=rpc("eth_getTransactionByHash",[tx_hash])
        rc_obj=rpc("eth_getTransactionReceipt",[tx_hash])
        if not tx_obj:
            raise HTTPException(status_code=404, detail="Tx not found")
        if not rc_obj:
            raise HTTPException(status_code=409, detail="Receipt not found")

    with log_section("[3/5] Normalize metadata"):
        block_hex=tx_obj.get("blockNumber")
        block_int=int(block_hex,16) if block_hex else None
        tx_meta={
            "hash":tx_obj.get("hash"),
            "from":tx_obj.get("from"),
            "to":tx_obj.get("to"),
            "blockNumber":block_hex,
            "blockNumberInt":block_int,
            "status":rc_obj.get("status")
        }
        log.debug("tx_meta=%s", tx_meta)

    with log_section("[4/5] Decode ERC-20 logs"):
        decoded_events=decode_erc20_logs(rc_obj)
        log.info("decoded_events_count=%d", len(decoded_events))
        if not decoded_events:
            return {
                "risk_assessment":{
                    "risk_level":"low",
                    "confidence":0.7,
                    "factors_triggered":[],
                    "rationale":"No ERC-20 events found."
                },
                "tx_meta":tx_meta,
                "decoded_events":decoded_events,
                "generated_at":datetime.now(timezone.utc).isoformat(),
            }

    with log_section("[5/5] Enrich & assess risk"):
        enrichment={
            "totals_by_token":aggregate_totals_by_token(decoded_events,tx_meta.get("from")),
            "heuristic_hints":generate_heuristic_hints(decoded_events)
        }
        log.debug("enrichment=%s", enrichment)

        try:
            risk_assessment = call_gemini_for_risk(tx_meta, decoded_events, enrichment["heuristic_hints"])
            log.debug("risk_assessment=%s", risk_assessment)
        except Exception as e:
            # Keep logs tidy: warning without full traceback
            log.warning("LLM step failed (%s); using heuristic fallback.", e)
            risk_assessment = heuristic_risk_fallback(tx_meta, decoded_events, enrichment["heuristic_hints"])

    return {
        "risk_assessment":risk_assessment,
        "tx_meta":tx_meta,
        "decoded_events":decoded_events,
        "enrichment":enrichment,
        "generated_at":datetime.now(timezone.utc).isoformat()
    }

# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status":"ok","time":datetime.now(timezone.utc).isoformat()}

@app.get("/txsec")
@app.post("/txsec")
def txsec(tx: Optional[str] = Query(None), body: Optional[TxBody] = Body(None)):
    tx_hash = tx or (body.tx if body else None)
    if not tx_hash:
        raise HTTPException(status_code=400, detail="Missing tx hash")
    result = analyze_tx_core(tx_hash)
    return JSONResponse(result)

@app.get("/txsec/download")
def txsec_download(tx: str=Query(...)):
    r=requests.get("http://127.0.0.1:8000/txsec",params={"tx":tx},timeout=120)
    if r.status_code!=200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    content=r.json()
    fname=f"tx_{tx[2:]}.json"
    blob=json.dumps(content,indent=2).encode("utf-8")
    return StreamingResponse(
        iter([blob]),
        media_type="application/json",
        headers={"Content-Disposition":f'attachment; filename="{fname}"'}
    )

# --------------------------------------------------------------------------
# CLI entrypoint
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Tx Security Analyzer CLI")
    parser.add_argument("--tx", required=True, help="Transaction hash (0x...)")
    parser.add_argument("--out", default=None, help="Output directory (if omitted, prints to stdout)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    args = parser.parse_args()

    # Adjust console log level
    if args.verbose >= 2:
        log.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.WARNING)
        
    # ANSI colors
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    # Banner
    log.info("Starting analysis for tx=%s", args.tx)

    tx_hash = args.tx.strip()
    if not isinstance(tx_hash, str) or not tx_hash.startswith("0x") or len(tx_hash) != 66:
        print(f"{RED}❌ Error: Invalid transaction hash{RESET}", file=sys.stderr)
        sys.exit(1)

    try:
        result = analyze_tx_core(tx_hash)
    except Exception as e:
        # Also print a user-friendly line to stderr
        print(f"{RED}❌ Error analyzing tx: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    blob = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        out_path = os.path.join(args.out, f"tx_{tx_hash[2:]}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(blob)
        # ✅ Only print the risk assessment
        # print(json.dumps(result.get("risk_assessment", {}), indent=2, ensure_ascii=False))
        
        risk = result.get("risk_assessment", {})
        risk_level = risk.get("risk_level", "unknown").capitalize()
        confidence = risk.get("confidence", 0)

        # Pick color based on risk level
        color = GREEN
        if risk_level.lower() == "medium":
            color = YELLOW
        elif risk_level.lower() == "high":
            color = RED

        print(f"{color}✅ Analysis Completed{RESET}")
        print(f"{color}Risk Level   : {risk_level}{RESET}")
        print(f"{color}Confidence   : {confidence:.2f}{RESET}")
        if risk.get("factors_triggered"):
            print(f"{color}Factors      : {', '.join(risk.get('factors_triggered', []))}{RESET}")
        else:
            print(f"{color}Factors      : None{RESET}")
        print(f"{color}Rationale    : {risk.get('rationale', 'No rationale provided.')}{RESET}")
        
        print(f"Saved JSON to {out_path}")
    else:
        print(blob)

def run_api():
    """Convenience entrypoint for starting the API via a console script."""
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    # If you run `python app.py --tx ...`, behave like the CLI.
    # If you run plain `python app.py` (no flags), start the API server.
    if any(a.startswith("--") for a in sys.argv[1:]):
        main()
    else:
        run_api()
