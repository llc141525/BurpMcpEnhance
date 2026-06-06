# tests/test_caido_mcp.py
"""Smoke tests for caido_mcp — no live Caido required."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))


def test_import_caido_mcp():
    """Module should import without errors (no live Caido needed)."""
    import caido_mcp  # noqa: F401
    assert hasattr(caido_mcp, "app")


def test_gql_raises_without_api_key(monkeypatch):
    """_gql should raise RuntimeError when CAIDO_API_KEY is not set."""
    import caido_mcp
    monkeypatch.setattr(caido_mcp, "API_KEY", "")
    try:
        caido_mcp._gql("{ __typename }")
        assert False, "should have raised"
    except RuntimeError as e:
        assert "CAIDO_API_KEY" in str(e)
