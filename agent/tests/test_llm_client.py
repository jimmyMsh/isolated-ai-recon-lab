"""Tests for the Ollama LLM client module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from config import AgentConfig, StageConfig
from llm_client import LLMClient, LLMError, LLMResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok_response(content_dict: dict) -> MagicMock:
    """Build a mock requests.Response with 200 status and valid JSON content."""
    content_str = json.dumps(content_dict)
    resp = MagicMock()
    resp.status_code = 200
    resp.ok = True
    resp.json.return_value = {"message": {"content": content_str}}
    resp.text = json.dumps({"message": {"content": content_str}})
    return resp


def _error_response(status_code: int, body: str = "error") -> MagicMock:
    """Build a mock requests.Response with a non-2xx status code."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.text = body
    return resp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config():
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
    )


@pytest.fixture()
def stage_config():
    return StageConfig(temperature=0.0, top_p=1.0, top_k=20)


@pytest.fixture()
def client(config, monkeypatch):
    mock_session = MagicMock(spec=requests.Session)
    monkeypatch.setattr("llm_client.requests.Session", lambda: mock_session)
    c = LLMClient(config)
    return c


@pytest.fixture()
def mock_post(client):
    """Return the mock post method from the client's session."""
    return client._session.post


# ---------------------------------------------------------------------------
# TestLLMClientInit
# ---------------------------------------------------------------------------


class TestLLMClientInit:
    def test_creates_session(self, config, monkeypatch):
        created = []
        original_mock = MagicMock(spec=requests.Session)

        def track_session():
            created.append(True)
            return original_mock

        monkeypatch.setattr("llm_client.requests.Session", track_session)
        LLMClient(config)
        assert len(created) == 1

    def test_stores_endpoint(self, client):
        assert client._endpoint == "http://localhost:11434/api/chat"


# ---------------------------------------------------------------------------
# TestResolveOptions
# ---------------------------------------------------------------------------


class TestResolveOptions:
    def test_with_stage_config(self, client, stage_config):
        opts = client._resolve_options(stage_config)
        assert opts["temperature"] == 0.0
        assert opts["top_p"] == 1.0
        assert opts["top_k"] == 20
        assert opts["num_ctx"] == 8192

    def test_without_stage_config(self, client):
        opts = client._resolve_options(None)
        assert opts["temperature"] == 0.7
        assert opts["top_p"] == 0.8
        assert opts["top_k"] == 20
        assert opts["num_ctx"] == 8192

    def test_custom_num_ctx(self, monkeypatch):
        config = AgentConfig(
            ollama_url="http://localhost:11434",
            model="qwen3:8b",
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
            nmap_path="/usr/bin/nmap",
            num_ctx=4096,
        )
        monkeypatch.setattr("llm_client.requests.Session", lambda: MagicMock(spec=requests.Session))
        c = LLMClient(config)
        opts = c._resolve_options(StageConfig())
        assert opts["num_ctx"] == 4096


# ---------------------------------------------------------------------------
# TestBuildRequestBody
# ---------------------------------------------------------------------------


class TestBuildRequestBody:
    def test_body_with_stage_config(self, client, stage_config):
        messages = [{"role": "user", "content": "hello"}]
        schema = {"type": "object"}
        body = client._build_request_body(messages, schema, stage_config)

        assert body["model"] == "qwen3:8b"
        assert body["messages"] is messages
        assert body["format"] is schema
        assert body["stream"] is False
        assert body["think"] is False
        assert body["options"]["temperature"] == 0.0

    def test_body_without_stage_config(self, client):
        messages = [{"role": "user", "content": "hello"}]
        schema = {"type": "object"}
        body = client._build_request_body(messages, schema, None)

        assert body["options"]["temperature"] == 0.7
        assert body["options"]["top_p"] == 0.8

    def test_messages_passed_verbatim(self, client):
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
        ]
        body = client._build_request_body(messages, {}, None)
        assert body["messages"] is messages

    def test_schema_passed_as_format(self, client):
        schema = {"type": "object", "properties": {"x": {"type": "string"}}}
        body = client._build_request_body([], schema, None)
        assert body["format"] is schema

    def test_think_false_always_present(self, client, stage_config):
        body_with = client._build_request_body([], {}, stage_config)
        body_without = client._build_request_body([], {}, None)
        assert body_with["think"] is False
        assert body_without["think"] is False

    def test_stream_false_always_present(self, client, stage_config):
        body = client._build_request_body([], {}, stage_config)
        assert body["stream"] is False


# ---------------------------------------------------------------------------
# TestRetryConnectionErrors
# ---------------------------------------------------------------------------


class TestRetryConnectionErrors:
    def test_connection_refused_retries_3_times_then_raises(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.side_effect = requests.ConnectionError("refused")

        with pytest.raises(LLMError, match="Connection failed"):
            client.call([], {})

        assert mock_post.call_count == 4  # 1 initial + 3 retries

    def test_timeout_retries_3_times_then_raises(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.side_effect = requests.Timeout("timed out")

        with pytest.raises(LLMError, match="Connection failed"):
            client.call([], {})

        assert mock_post.call_count == 4

    def test_connection_error_succeeds_on_retry(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.side_effect = [
            requests.ConnectionError("refused"),
            _ok_response({"action": "scan"}),
        ]

        result = client.call([], {})
        assert result.parsed == {"action": "scan"}
        assert mock_post.call_count == 2

    def test_connection_retry_waits_3_seconds(self, client, mock_post, monkeypatch):
        sleeps = []
        monkeypatch.setattr("llm_client.time.sleep", lambda s: sleeps.append(s))
        mock_post.side_effect = [
            requests.ConnectionError("refused"),
            _ok_response({"ok": True}),
        ]

        client.call([], {})
        assert sleeps == [3]


# ---------------------------------------------------------------------------
# TestRetryServerErrors
# ---------------------------------------------------------------------------


class TestRetryServerErrors:
    def test_http_500_retries_2_times_then_raises(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.return_value = _error_response(500)

        with pytest.raises(LLMError, match="500"):
            client.call([], {})

        assert mock_post.call_count == 3  # 1 initial + 2 retries

    def test_http_503_retries_2_times_then_raises(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.return_value = _error_response(503)

        with pytest.raises(LLMError, match="503"):
            client.call([], {})

        assert mock_post.call_count == 3

    def test_http_500_succeeds_on_retry(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.side_effect = [
            _error_response(500),
            _ok_response({"result": "ok"}),
        ]

        result = client.call([], {})
        assert result.parsed == {"result": "ok"}

    def test_server_error_retry_waits_5_seconds(self, client, mock_post, monkeypatch):
        sleeps = []
        monkeypatch.setattr("llm_client.time.sleep", lambda s: sleeps.append(s))
        mock_post.side_effect = [
            _error_response(500),
            _ok_response({"ok": True}),
        ]

        client.call([], {})
        assert sleeps == [5]

    def test_http_400_fails_immediately(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.return_value = _error_response(400)

        with pytest.raises(LLMError, match="400"):
            client.call([], {})

        assert mock_post.call_count == 1

    def test_http_404_fails_immediately(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.return_value = _error_response(404)

        with pytest.raises(LLMError, match="404"):
            client.call([], {})

        assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# TestRetryInvalidJSON
# ---------------------------------------------------------------------------


class TestRetryInvalidJSON:
    def test_invalid_outer_json_retries_once(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        bad_resp = MagicMock()
        bad_resp.status_code = 200
        bad_resp.ok = True
        bad_resp.json.side_effect = ValueError("not json")

        mock_post.side_effect = [bad_resp, _ok_response({"a": 1})]

        result = client.call([], {})
        assert result.parsed == {"a": 1}
        assert mock_post.call_count == 2

    def test_invalid_outer_json_exhausted(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        bad_resp = MagicMock()
        bad_resp.status_code = 200
        bad_resp.ok = True
        bad_resp.json.side_effect = ValueError("not json")

        mock_post.return_value = bad_resp

        with pytest.raises(LLMError, match="Invalid JSON"):
            client.call([], {})

        assert mock_post.call_count == 2  # 1 initial + 1 retry

    def test_invalid_inner_json_retries_once(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        bad_inner = MagicMock()
        bad_inner.status_code = 200
        bad_inner.ok = True
        bad_inner.json.return_value = {"message": {"content": "not-valid-json{"}}

        mock_post.side_effect = [bad_inner, _ok_response({"b": 2})]

        result = client.call([], {})
        assert result.parsed == {"b": 2}

    def test_invalid_inner_json_exhausted(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        bad_inner = MagicMock()
        bad_inner.status_code = 200
        bad_inner.ok = True
        bad_inner.json.return_value = {"message": {"content": "not-valid-json{"}}

        mock_post.return_value = bad_inner

        with pytest.raises(LLMError, match="Invalid JSON"):
            client.call([], {})


# ---------------------------------------------------------------------------
# TestRetryEmptyContent
# ---------------------------------------------------------------------------


class TestRetryEmptyContent:
    def test_empty_content_retries_once(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        empty_resp = MagicMock()
        empty_resp.status_code = 200
        empty_resp.ok = True
        empty_resp.json.return_value = {"message": {"content": ""}}

        mock_post.side_effect = [empty_resp, _ok_response({"c": 3})]

        result = client.call([], {})
        assert result.parsed == {"c": 3}

    def test_empty_content_exhausted(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        empty_resp = MagicMock()
        empty_resp.status_code = 200
        empty_resp.ok = True
        empty_resp.json.return_value = {"message": {"content": ""}}

        mock_post.return_value = empty_resp

        with pytest.raises(LLMError, match="Empty content"):
            client.call([], {})

    def test_whitespace_only_treated_as_empty(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        ws_resp = MagicMock()
        ws_resp.status_code = 200
        ws_resp.ok = True
        ws_resp.json.return_value = {"message": {"content": "  \n  "}}

        mock_post.side_effect = [ws_resp, _ok_response({"d": 4})]

        result = client.call([], {})
        assert result.parsed == {"d": 4}

    def test_missing_message_key_treated_as_empty(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        no_msg = MagicMock()
        no_msg.status_code = 200
        no_msg.ok = True
        no_msg.json.return_value = {"other": "data"}

        mock_post.side_effect = [no_msg, _ok_response({"e": 5})]

        result = client.call([], {})
        assert result.parsed == {"e": 5}

    def test_null_message_treated_as_empty(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        null_msg = MagicMock()
        null_msg.status_code = 200
        null_msg.ok = True
        null_msg.json.return_value = {"message": None}

        mock_post.side_effect = [null_msg, _ok_response({"f": 6})]

        result = client.call([], {})
        assert result.parsed == {"f": 6}

    def test_non_dict_message_treated_as_empty(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)

        str_msg = MagicMock()
        str_msg.status_code = 200
        str_msg.ok = True
        str_msg.json.return_value = {"message": "oops"}

        mock_post.side_effect = [str_msg, _ok_response({"g": 7})]

        result = client.call([], {})
        assert result.parsed == {"g": 7}


# ---------------------------------------------------------------------------
# TestCall
# ---------------------------------------------------------------------------


class TestCall:
    def test_happy_path_returns_llm_response(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        payload = {"action": "scan", "target": "192.168.56.0/24"}
        mock_post.return_value = _ok_response(payload)

        result = client.call(
            [{"role": "user", "content": "plan"}],
            {"type": "object"},
            StageConfig(),
        )

        assert isinstance(result, LLMResponse)
        assert result.parsed == payload
        assert result.thinking is None

    def test_raw_content_preserved(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        payload = {"key": "value"}
        mock_post.return_value = _ok_response(payload)

        result = client.call([], {})
        assert result.raw_content == json.dumps(payload)

    def test_schema_passed_as_format_in_post(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        schema = {"type": "object", "properties": {"x": {"type": "integer"}}}
        mock_post.return_value = _ok_response({"x": 1})

        client.call([], schema)

        posted_body = mock_post.call_args.kwargs["json"]
        assert posted_body["format"] is schema

    def test_stage_config_flows_to_options(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        sc = StageConfig(temperature=0.1, top_p=0.9, top_k=40)
        mock_post.return_value = _ok_response({"ok": True})

        client.call([], {}, stage_config=sc)

        posted_body = mock_post.call_args.kwargs["json"]
        assert posted_body["options"]["temperature"] == 0.1
        assert posted_body["options"]["top_p"] == 0.9
        assert posted_body["options"]["top_k"] == 40

    def test_post_uses_correct_endpoint_and_timeout(self, client, mock_post, monkeypatch):
        monkeypatch.setattr("llm_client.time.sleep", lambda _: None)
        mock_post.return_value = _ok_response({"ok": True})

        client.call([], {})

        args, kwargs = mock_post.call_args
        assert args[0] == "http://localhost:11434/api/chat"
        assert kwargs["timeout"] == 120


# ---------------------------------------------------------------------------
# TestLLMResponse
# ---------------------------------------------------------------------------


class TestLLMResponse:
    def test_fields_accessible(self):
        r = LLMResponse(parsed={"a": 1}, raw_content='{"a": 1}')
        assert r.parsed == {"a": 1}
        assert r.raw_content == '{"a": 1}'

    def test_thinking_defaults_to_none(self):
        r = LLMResponse(parsed={}, raw_content="{}")
        assert r.thinking is None

    def test_raw_content_preserved_verbatim(self):
        raw = '{"a":1, "b" :  2}'
        r = LLMResponse(parsed={"a": 1, "b": 2}, raw_content=raw)
        assert r.raw_content == raw


# ---------------------------------------------------------------------------
# TestLLMError
# ---------------------------------------------------------------------------


class TestLLMError:
    def test_is_exception(self):
        assert isinstance(LLMError(), Exception)

    def test_preserves_message(self):
        assert str(LLMError("test error")) == "test error"
