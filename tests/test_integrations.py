from unittest.mock import AsyncMock, MagicMock, patch

from tracker import integrations


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    return resp


async def test_lookup_ioc_calls_enrich_endpoint():
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({"indicator": "1.2.3.4", "verdict": "malicious"})
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.integrations.httpx.AsyncClient", return_value=mock_client):
        result = await integrations.lookup_ioc("1.2.3.4")

    assert result["verdict"] == "malicious"
    mock_client.get.assert_called_once()
    call_kwargs = mock_client.get.call_args
    assert call_kwargs[1]["params"] == {"indicator": "1.2.3.4", "checks": "all"}


async def test_lookup_ioc_sends_api_key_header_when_configured(monkeypatch):
    monkeypatch.setattr(integrations, "IOC_API_KEY", "test-key-123")
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({"indicator": "x", "verdict": "clean"})
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.integrations.httpx.AsyncClient", return_value=mock_client):
        await integrations.lookup_ioc("x")

    headers = mock_client.get.call_args[1]["headers"]
    assert headers == {"X-API-Key": "test-key-123"}


async def test_lookup_ioc_no_key_header_when_not_configured(monkeypatch):
    monkeypatch.setattr(integrations, "IOC_API_KEY", None)
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({"indicator": "x", "verdict": "clean"})
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.integrations.httpx.AsyncClient", return_value=mock_client):
        await integrations.lookup_ioc("x")

    headers = mock_client.get.call_args[1]["headers"]
    assert headers == {}


async def test_analyze_phishing_with_raw_text():
    mock_client = AsyncMock()
    mock_client.post.return_value = _mock_response({"verdict": "phishing"})
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.integrations.httpx.AsyncClient", return_value=mock_client):
        result = await integrations.analyze_phishing(raw_text="suspicious email body")

    assert result["verdict"] == "phishing"
    call_kwargs = mock_client.post.call_args[1]
    assert call_kwargs["data"] == {"raw_text": "suspicious email body"}


async def test_analyze_phishing_with_file():
    mock_client = AsyncMock()
    mock_client.post.return_value = _mock_response({"verdict": "suspicious"})
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.integrations.httpx.AsyncClient", return_value=mock_client):
        result = await integrations.analyze_phishing(file_bytes=b"raw eml bytes", filename="test.eml")

    assert result["verdict"] == "suspicious"
    call_kwargs = mock_client.post.call_args[1]
    assert "file" in call_kwargs["files"]


async def test_analyze_file_sends_api_key_when_configured(monkeypatch):
    monkeypatch.setattr(integrations, "FILE_ANALYSER_API_KEY", "file-key-456")
    mock_client = AsyncMock()
    mock_client.post.return_value = _mock_response({"verdict": "malicious", "filename": "evil.exe"})
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.integrations.httpx.AsyncClient", return_value=mock_client):
        result = await integrations.analyze_file(b"fake exe bytes", "evil.exe")

    assert result["verdict"] == "malicious"
    headers = mock_client.post.call_args[1]["headers"]
    assert headers == {"X-API-Key": "file-key-456"}
