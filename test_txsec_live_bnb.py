# tests/test_txsec_live_bnb.py
# ---------------------------------------------------------------------------
# Live BNB Chain integration tests for TxSec
# ---------------------------------------------------------------------------
# These tests use REAL transaction hashes from BNB Smart Chain mainnet.
# Ensure your .env ETH_RPC_URL points to a working BSC RPC node:
# ETH_RPC_URL="https://bsc-dataseed.bnbchain.org"
# ---------------------------------------------------------------------------

import pytest
import app

# Real BNB Chain hashes (confirmed transactions)
REAL_TX_HASHES = {
    "MULTIPLE_TRANSFERS": "0xc7112d1844ef0a5b574659f53af431b4dd264ff0d870d1a917602021db28d78a",
    "APPROVAL":           "0x6a7f0ed21d0634d5fc4a5de2cc21ccfffd23287c2b41857fc6a272f54fc667fd",
    "RANDOM_LOW_ACTIVITY": "0x9be9897ae3ad45371c082b7f442a8b3596d945360f6c434ff4f79bb66780e454",
}

@pytest.mark.live
def test_live_multiple_transfers():
    """
    Run analysis for a real BNB Chain transaction with multiple Transfers.
    """
    tx_hash = REAL_TX_HASHES["MULTIPLE_TRANSFERS"]
    result = app.analyze_tx_core(tx_hash)

    assert "tx_meta" in result
    assert "decoded_events" in result
    assert isinstance(result["decoded_events"], list)
    assert "risk_assessment" in result
    print("\n[Multiple Transfers] Risk:", result["risk_assessment"])

@pytest.mark.live
def test_live_approval_tx():
    """
    Run analysis for a real BNB Chain transaction containing an Approval event.
    """
    tx_hash = REAL_TX_HASHES["APPROVAL"]
    result = app.analyze_tx_core(tx_hash)

    decoded = result.get("decoded_events", [])
    approvals = [e for e in decoded if e.get("type") == "Approval"]
    assert len(decoded) > 0
    assert "risk_assessment" in result
    print("\n[Approval Tx] Risk:", result["risk_assessment"])

@pytest.mark.live
def test_live_random_tx():
    """
    Run analysis for a random low-activity BNB Chain transaction.
    """
    tx_hash = REAL_TX_HASHES["RANDOM_LOW_ACTIVITY"]
    result = app.analyze_tx_core(tx_hash)
    assert "risk_assessment" in result
    print("\n[Random Tx] Risk:", result["risk_assessment"])

@pytest.mark.live
def test_invalid_tx_hash():
    """
    Invalid tx hash should raise HTTP 400 error.
    """
    bad_hash = "0x123"
    with pytest.raises(app.HTTPException) as excinfo:
        app.analyze_tx_core(bad_hash)
    assert excinfo.value.status_code == 400
    assert "Invalid tx hash" in str(excinfo.value.detail)
