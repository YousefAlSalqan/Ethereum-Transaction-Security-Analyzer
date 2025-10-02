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
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
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
        log.exception("%s ...failed", title); raise

load_dotenv()
ETH_RPC_URL    = os.getenv("ETH_RPC_URL", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

if not ETH_RPC_URL:
    raise RuntimeError("ETH_RPC_URL is not set (.env or environment).")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set (.env or environment).")

genai.configure(api_key=GEMINI_API_KEY)
