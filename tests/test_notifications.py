from unittest.mock import AsyncMock, patch

from tracker import notifications


async def test_notify_calls_both_channels():
    with patch("tracker.notifications.telegram_bot.notify_all", new_callable=AsyncMock) as mock_telegram, \
         patch("tracker.notifications.email_notifier.send_email", new_callable=AsyncMock) as mock_email:
        await notifications.notify("Test Subject", "Test Body")

    mock_telegram.assert_called_once_with("Test Body")
    mock_email.assert_called_once_with("Test Subject", "Test Body")
