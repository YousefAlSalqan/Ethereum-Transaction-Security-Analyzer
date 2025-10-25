##Ethereum-Transaction-Security-Analyzer##
Ethereum-Transaction-Security-Analyzer is a minimal command-line and API tool that analyzes an EVM transaction hash (Ethereum, BSC, etc.) to produce a structured JSON report containing:
Transaction metadata
Decoded ERC-20 Transfer and Approval events
Heuristic enrichment
LLM-based risk assessment using Google Gemini 

##Overview## 
TxSec fetches a transaction by hash from a public JSON-RPC endpoint, decodes ERC-20 logs, and runs an LLM-powered risk triage to determine if a transaction looks low, suspicious, or high risk, with explanations.
It can be used either as:
A CLI tool (txsec)
A FastAPI service (txsec-api)

##Requirements## 
Python 3.9+
Internet access
Valid EVM JSON-RPC URL (e.g., Infura, Alchemy)
Valid Google Gemini API key

##Environment Configuration## 
Detailed in .env 

##CLI Usage##
Analyze a transaction: 
txsec --tx 0x<transaction_hash> --out ./out -v
This creates a file: 
./out/tx_<hash>.json
| Flag        | Description                            |
| ----------- | -------------------------------------- |
| `--tx`      | Required 66-character transaction hash |
| `--out`     | Optional output directory              |
| `-v`, `-vv` | Verbosity level                        |
Example Analysis:
✅ Analysis Completed
Risk Level   : High
Confidence   : 0.92
Factors      : infinite approval, phishing spender
Rationale    : MAX_UINT256 approval to known drainer address.
Saved JSON to ./out/tx_794a7a....json

##LLM Risk Assessment##
TxSec uses Google Gemini via google-generativeai SDK.
Prompt factors considered include:
Unusually large or infinite ERC-20 approvals
Rapid/multi-hop token movements
Multiple transfers to fresh EOAs
Phishing or rug-pull-like behavior
LLM returns strictly structured JSON:
{
  "risk_level": "low|suspicious|high",
  "confidence": 0.0,
  "factors_triggered": ["..."],
  "rationale": "short explanation"
}
If Gemini fails or times out, TxSec automatically falls back to heuristic risk estimation.

##API Mode##
txsec-api
or 
uvicorn app:app --host 0.0.0.0 --port 8000
Endpoints: 
| Method | Endpoint                      | Description                   |
| ------ | ----------------------------- | ----------------------------- |
| `GET`  | `/health`                     | Health check                  |
| `GET`  | `/txsec?tx=0x<hash>`          | Analyze a tx                  |
| `POST` | `/txsec`                      | JSON body `{ "tx": "0x..." }` |
| `GET`  | `/txsec/download?tx=0x<hash>` | Download JSON result          |

##Example Output Structure
{
  "risk_assessment": {
    "risk_level": "suspicious",
    "confidence": 0.78,
    "factors_triggered": ["multiple approvals"],
    "rationale": "Two approvals to new addresses within one tx."
  },
  "tx_meta": {
    "hash": "0x...",
    "from": "0x...",
    "to": "0x...",
    "blockNumber": "0x...",
    "status": "0x1"
  },
  "decoded_events": [...],
  "enrichment": {
    "totals_by_token": {...},
    "heuristic_hints": [...]
  },
  "generated_at": "2025-10-25T09:00:00Z"
}


