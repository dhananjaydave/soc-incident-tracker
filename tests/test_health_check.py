from unittest.mock import AsyncMock, MagicMock, patch

from tracker import health_check


def _mock_response(status_code):
    resp = MagicMock()
    resp.status_code = status_code
    return resp


async def test_check_internal_tools_all_up():
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response(200)
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.health_check.httpx.AsyncClient", return_value=mock_client):
        down = await health_check.check_internal_tools()

    assert down == []


async def test_check_internal_tools_one_down():
    call_count = {"n": 0}

    async def fake_get(url):
        call_count["n"] += 1
        if "8002" in url:
            raise ConnectionError("refused")
        return _mock_response(200)

    mock_client = AsyncMock()
    mock_client.get.side_effect = fake_get
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.health_check.httpx.AsyncClient", return_value=mock_client):
        down = await health_check.check_internal_tools()

    assert down == ["Phishing Triage"]


async def test_check_internal_tools_non_200_counts_as_down():
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response(500)
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.health_check.httpx.AsyncClient", return_value=mock_client):
        down = await health_check.check_internal_tools()

    assert len(down) == 3


async def test_check_internal_tools_all_down():
    mock_client = AsyncMock()
    mock_client.get.side_effect = ConnectionError("refused")
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.health_check.httpx.AsyncClient", return_value=mock_client):
        down = await health_check.check_internal_tools()

    assert set(down) == {"IOC Enrichment", "Phishing Triage", "File Analyser"}
