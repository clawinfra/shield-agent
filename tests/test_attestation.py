"""Tests for ClawChain attestation module."""

import time

from shield_agent.attestation import (
    AttestationResult,
    compute_scan_hash,
    attest_scan,
)
from shield_agent.models import RiskLevel, ScanResult, Vulnerability


def _make_scan_result(**overrides) -> ScanResult:
    """Create a ScanResult with sensible defaults."""
    defaults = {
        "contract_address": "0xDEADBEEF",
        "contract_name": "TestContract",
        "scan_timestamp": 1700000000.0,
        "vulnerabilities": [],
        "risk_score": 0,
        "risk_level": RiskLevel.LOW,
        "source_available": True,
    }
    defaults.update(overrides)
    return ScanResult(**defaults)


class TestComputeScanHash:
    """Tests for ``compute_scan_hash``."""

    def test_deterministic_same_input(self):
        """Same ScanResult always produces the same hash."""
        result = _make_scan_result()
        hash1 = compute_scan_hash(result)
        hash2 = compute_scan_hash(result)
        assert hash1 == hash2

    def test_hash_is_hex_string(self):
        """Hash is a 64-char hex string (SHA-256)."""
        result = _make_scan_result()
        h = compute_scan_hash(result)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_changes_with_different_address(self):
        """Different contract address → different hash."""
        r1 = _make_scan_result(contract_address="0xAAAA")
        r2 = _make_scan_result(contract_address="0xBBBB")
        assert compute_scan_hash(r1) != compute_scan_hash(r2)

    def test_hash_changes_with_different_score(self):
        """Different risk score → different hash."""
        r1 = _make_scan_result(risk_score=10)
        r2 = _make_scan_result(risk_score=90)
        assert compute_scan_hash(r1) != compute_scan_hash(r2)

    def test_hash_changes_with_different_vuln_count(self):
        """Different vulnerability count → different hash."""
        vuln = Vulnerability(
            type="reentrancy", description="test", severity=RiskLevel.HIGH
        )
        r1 = _make_scan_result(vulnerabilities=[])
        r2 = _make_scan_result(vulnerabilities=[vuln])
        assert compute_scan_hash(r1) != compute_scan_hash(r2)

    def test_hash_changes_with_different_timestamp(self):
        """Different scan timestamp → different hash."""
        r1 = _make_scan_result(scan_timestamp=1000.0)
        r2 = _make_scan_result(scan_timestamp=2000.0)
        assert compute_scan_hash(r1) != compute_scan_hash(r2)


class TestAttestScan:
    """Tests for ``attest_scan``."""

    def test_returns_attestation_result(self):
        """attest_scan returns an AttestationResult dataclass."""
        result = _make_scan_result()
        att = attest_scan(result)
        assert isinstance(att, AttestationResult)

    def test_stub_mode_succeeds(self):
        """Stub mode always returns success=True."""
        result = _make_scan_result()
        att = attest_scan(result)
        assert att.success is True
        assert att.error is None

    def test_tx_hash_is_hex(self):
        """The (stubbed) tx_hash starts with 0x and is hex."""
        result = _make_scan_result()
        att = attest_scan(result)
        assert att.tx_hash is not None
        assert att.tx_hash.startswith("0x")
        hex_part = att.tx_hash[2:]
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_different_results_different_tx_hash(self):
        """Different scan results produce different tx hashes."""
        r1 = _make_scan_result(contract_address="0xAAAA", risk_score=10)
        r2 = _make_scan_result(contract_address="0xBBBB", risk_score=90)
        att1 = attest_scan(r1)
        att2 = attest_scan(r2)
        assert att1.tx_hash != att2.tx_hash

    def test_block_number_is_none_in_stub(self):
        """In stub mode, block_number should be None."""
        result = _make_scan_result()
        att = attest_scan(result)
        assert att.block_number is None

    def test_custom_agent_id(self):
        """attest_scan accepts a custom agent_id without error."""
        result = _make_scan_result()
        att = attest_scan(result, agent_id="custom-agent-v2")
        assert att.success is True
