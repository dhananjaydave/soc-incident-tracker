from unittest.mock import AsyncMock, patch

from tracker import notifications


async def test_notify_sends_subject_and_body_to_telegram():
    with patch("tracker.notifications.telegram_bot.notify_all", new_callable=AsyncMock) as mock_telegram:
        await notifications.notify("Test Subject", "Test Body")

    mock_telegram.assert_called_once_with("Test Subject\nTest Body")
