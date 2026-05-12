"""Sentinel KQL artifacts: presence and basic shape."""
from pathlib import Path

KQL_DIR = Path(__file__).resolve().parent.parent / "kql"
EXPECTED = (
    "intune_mass_wipe_retire_burst.kql",
    "intune_policy_change_velocity.kql",
    "entra_privileged_intune_window.kql",
)


def test_three_kql_files():
    files = {p.name for p in KQL_DIR.glob("*.kql")}
    assert files == set(EXPECTED)


def test_kql_queries_use_auditlogs():
    for name in EXPECTED:
        text = (KQL_DIR / name).read_text()
        assert "AuditLogs" in text
        assert "where" in text.lower()
