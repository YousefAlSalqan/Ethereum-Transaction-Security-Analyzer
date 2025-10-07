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
from collections import defaultdict
from functools import lru_cache
from contextlib import contextmanager

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
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

def rpc(method: str, params: List[Any]) -> Dict[str, Any]:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    r = requests.post(ETH_RPC_URL, json=payload, timeout=50)
    r.raise_for_status()
    data = r.json()
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

app = FastAPI(title="Tx Risk Triage", version="0.1")
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

TRANSFER_SIG = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL_SIG = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
MAX_UINT256  = int("f"*64, 16)

def decode_erc20_logs(receipt: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for lg in (receipt.get("logs", []) or []):
        topics = [str(t).lower() for t in (lg.get("topics") or [])]
        if not topics:
            continue
        t0 = topics[0]
        token = (lg.get("address") or "").lower()
        if not token:
            continue
        meta = get_erc20_metadata(token)
        symbol, decimals = meta.get("symbol"), meta.get("decimals")
        if t0 == TRANSFER_SIG and len(topics) >= 3:
            events.append({
                "type": "Transfer",
                "contract": token,
                "from": to_address(topics[1]),
                "to": to_address(topics[2]),
                "value": hex_to_int_str(lg.get("data")),
                "logIndex": lg.get("logIndex"),
                "txIndex": lg.get("transactionIndex"),
                "symbol": symbol,
                "decimals": decimals,
            })
        elif t0 == APPROVAL_SIG and len(topics) >= 3:
            vstr = hex_to_int_str(lg.get("data"))
            is_inf, near_inf = False, False
            try:
                iv = int(vstr)
                is_inf = iv >= MAX_UINT256
                near_inf = iv >= MAX_UINT256 - 10
            except Exception:
                pass
            events.append({
                "type": "Approval",
                "contract": token,
                "owner": to_address(topics[1]),
                "spender": to_address(topics[2]),
                "value": vstr,
                "is_infinite": is_inf,
                "is_near_infinite": near_inf,
                "logIndex": lg.get("logIndex"),
                "txIndex": lg.get("transactionIndex"),
                "symbol": symbol,
                "decimals": decimals,
            })
    for ev in events:
        try:
            dec = ev.get("decimals")
            if dec is not None:
                ev["value_float"] = int(ev["value"]) / (10 ** int(dec))
        except Exception:
            pass
    return events

def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _hex_to_int_safe(h: str) -> int:
    try:
        return int(h, 16)
    except Exception:
        return -1

def canonicalize_event(ev: dict) -> Dict[str, Any]:
    out = {
        "type": str(ev.get("type","")),
        "contract": str(ev.get("contract","")).lower(),
        "logIndex": str(ev.get("logIndex","")),
        "txIndex": str(ev.get("txIndex","")),
    }
    if out["type"] == "Transfer":
        out |= {
            "from": str(ev.get("from","")).lower(),
            "to": str(ev.get("to","")).lower(),
            "value": str(ev.get("value","0"))
        }
    elif out["type"] == "Approval":
        out |= {
            "owner": str(ev.get("owner","")).lower(),
            "spender": str(ev.get("spender","")).lower(),
            "value": str(ev.get("value","0")),
            "is_infinite": bool(ev.get("is_infinite", False)),
            "is_near_infinite": bool(ev.get("is_near_infinite", False))
        }
    if isinstance(ev.get("decimals"), int):
        out["decimals"] = ev["decimals"]
    if isinstance(ev.get("symbol"), str):
        out["symbol"] = ev["symbol"].replace("\x00","")
    return out

def canonicalize_events(events: List[dict]) -> List[dict]:
    return sorted([canonicalize_event(e) for e in events],
                  key=lambda e: _hex_to_int_safe(e.get("logIndex","")))

def canonicalize_tx_meta(tx_meta: dict) -> dict:
    return {
        "hash": str(tx_meta.get("hash","")),
        "from": str(tx_meta.get("from","")).lower(),
        "to": str(tx_meta.get("to","")).lower(),
        "blockNumber": str(tx_meta.get("blockNumber","")),
        "status": str(tx_meta.get("status","")),
    }

def canonicalize_hints(hints: List[str]) -> List[str]:
    return sorted({h.strip() for h in hints if isinstance(h,str) and h.strip()})

MAX_EVENTS_FOR_PROMPT, PROMPT_HEAD, PROMPT_TAIL = 120, 80, 40

def build_stable_facts(tx_meta: dict, decoded_events: List[dict], hints: Optional[List[str]] = None) -> str:
    norm_events = canonicalize_events(decoded_events)
    truncated = False
    if len(norm_events) > MAX_EVENTS_FOR_PROMPT:
        truncated = True
        norm_events = norm_events[:PROMPT_HEAD] + norm_events[-PROMPT_TAIL:]
    facts = {"tx_meta": canonicalize_tx_meta(tx_meta), "decoded_events": norm_events}
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

def build_llm_prompt(tx_meta: Dict[str, Any], decoded_events: List[Dict[str, Any]], hints: Optional[List[str]]=None) -> str:
    schema = (
        'Return ONE JSON object with EXACTLY these keys:\n'
        '{"risk_level":"low|suspicious|high","confidence":<0..1>,'
        '"factors_triggered":["<string>",...],"rationale":"<<=280 chars>"}\n'
        'Rules:\n- Output MUST be valid JSON.\n- Only the keys above.\n'
        '- If "heuristic_hints" exists, include at least one accurate hint.\n'
        '- IMPORTANT: Return MINIFIED JSON.'
    )
    good = ('Example (GOOD):\n'
            '{"risk_level":"high","confidence":0.92,'
            '"factors_triggered":["infinite approval","known phishing spender"],'
            '"rationale":"MAX_UINT256 approval to 0xabc...; spender has phishing history."}')
    return ("You are a blockchain security triage assistant.\nBe precise, skeptical, and deterministic.\n\n"
            f"{schema}\n\n{good}\n\n"
            "Now assess the following transaction facts (JSON):\n"
            f"{build_stable_facts(tx_meta, decoded_events, hints)}\n\n"
            "Respond with MINIFIED JSON only. No prose.")

def normalize_risk_assessment(raw: Dict[str, Any]) -> Dict[str, Any]:
    result = {"risk_level":"low","confidence":0.5,"factors_triggered":[],"rationale":"No assessment."}
    if not isinstance(raw, dict):
        return result
    rl = str(raw.get("risk_level","low")).lower()
    if rl not in {"low","suspicious","high"}:
        rl = "low"
    result["risk_level"] = rl
    try:
        cf = float(raw.get("confidence",0.5))
        result["confidence"] = max(0.0,min(1.0,cf))
    except Exception:
        pass
    ft = raw.get("factors_triggered",[])
    if isinstance(ft,list):
        result["factors_triggered"] = [str(x) for x in ft if isinstance(x,(str,int,float))]
    result["rationale"] = str(raw.get("rationale") or "")[:280]
    return result

def heuristic_risk_fallback(tx_meta: Dict[str, Any], events: List[Dict[str, Any]], hints: List[str]) -> Dict[str, Any]:
    high = any("infinite" in (h or "").lower() for h in (hints or []))
    susp = any(("fan-out" in (h or "").lower()) or ("multiple approvals" in (h or "").lower()) for h in (hints or []))
    risk_level, confidence = ("high",0.85) if high else (("suspicious",0.7) if susp else ("low",0.6))
    rationale_bits = []
    if hints:
        rationale_bits.append("; ".join(hints[:3]))
    if not rationale_bits:
        rationale_bits.append("Heuristic only (LLM unavailable).")
    return {"risk_level":risk_level,"confidence":confidence,"factors_triggered":(hints or [])[:3],
            "rationale":(". ".join(rationale_bits))[:280]}

def call_gemini_for_risk(tx_meta: Dict[str, Any], decoded_events: List[Dict[str, Any]], heuristic_hints: Optional[List[str]]=None) -> Dict[str, Any]:
    prompt_text = build_llm_prompt(tx_meta, decoded_events, heuristic_hints)
    model = genai.GenerativeModel(
        GEMINI_MODEL,
        generation_config={"response_mime_type":"application/json","temperature":0.0,"candidate_count":1},
    )
    timeouts = [60, 120, 180]
    last_err: Optional[Exception] = None
    for t in timeouts:
        try:
            try:
                resp = model.generate_content(prompt_text, request_options={"timeout": t})
            except TypeError:
                resp = model.generate_content(prompt_text)
            content = (resp.text or "").strip()
            try:
                parsed = json.loads(content)
            except Exception:
                s,e = content.find("{"), content.rfind("}")
                parsed = json.loads(content[s:e+1]) if s!=-1 and e!=-1 and e>s else {}
            return normalize_risk_assessment(parsed)
        except Exception as e:
            last_err = e
            log.warning("Gemini attempt with timeout=%ss failed: %s", t, e)
    raise RuntimeError(f"Gemini generate_content failed after retries: {last_err}")
