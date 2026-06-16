"""Unit tests for etl_analyzer.py"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.etl_analyzer import analyze


@pytest.fixture
def mock_deepseek(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API", "test-key-xxx")
    with patch("utils.etl_analyzer.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"result": "test"}'
        mock_client.chat.completions.create.return_value = mock_response
        yield mock_client


def test_analyze_filter_burp_returns_string(mock_deepseek):
    result = analyze("filter_burp", '{"url": "/api/test"}')
    assert result == '{"result": "test"}'
    mock_deepseek.chat.completions.create.assert_called_once()


def test_analyze_uses_correct_model(mock_deepseek):
    analyze("filter_burp", "data")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    assert call_kwargs["model"] == "deepseek-chat"


def test_analyze_unknown_task_raises_value_error(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API", "test-key-xxx")
    with pytest.raises(ValueError, match="Unknown task"):
        analyze("nonexistent_task", "data")


def test_analyze_missing_api_key_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API", raising=False)
    with pytest.raises(RuntimeError, match="DEEPSEEK_API"):
        analyze("filter_burp", "data")


def test_analyze_instruction_prepended_to_data(mock_deepseek):
    analyze("filter_burp", "raw_data", instruction="extra context")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    user_msg = call_kwargs["messages"][1]["content"]
    assert "extra context" in user_msg
    assert "raw_data" in user_msg


def test_analyze_no_instruction_sends_data_only(mock_deepseek):
    analyze("filter_burp", "raw_data")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    user_msg = call_kwargs["messages"][1]["content"]
    assert user_msg == "raw_data"


@pytest.mark.parametrize(
    "task",
    [
        "filter_burp",
        "analyze_js",
        "filter_db",
        "extract_endpoints",
        "classify_business",
        "analyze_flow",
        "generate_variants",
        "diff_responses",
    ],
)
def test_all_tasks_have_system_prompts(task, mock_deepseek):
    result = analyze(task, "sample data")
    assert result is not None
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    system_msg = call_kwargs["messages"][0]["content"]
    assert len(system_msg) > 10
