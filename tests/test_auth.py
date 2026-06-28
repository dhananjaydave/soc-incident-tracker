import os

os.environ.setdefault("TRACKER_SECRET_KEY", "test-secret-key-not-for-production")

from tracker import auth


def test_password_hash_and_verify_roundtrip():
    hashed = auth.hash_password("correct-password")
    assert auth.verify_password("correct-password", hashed) is True


def test_wrong_password_rejected():
    hashed = auth.hash_password("correct-password")
    assert auth.verify_password("wrong-password", hashed) is False


def test_password_hash_is_not_plaintext():
    hashed = auth.hash_password("correct-password")
    assert "correct-password" not in hashed


def test_two_hashes_of_same_password_differ():
    """bcrypt salts automatically - confirms we're not doing anything that
    accidentally produces a deterministic, rainbow-table-able hash."""
    h1 = auth.hash_password("same-password")
    h2 = auth.hash_password("same-password")
    assert h1 != h2
    assert auth.verify_password("same-password", h1)
    assert auth.verify_password("same-password", h2)


def test_malformed_hash_does_not_crash_verify():
    assert auth.verify_password("anything", "not-a-real-bcrypt-hash") is False


def test_session_token_roundtrip():
    token = auth.create_session_token("admin")
    assert auth.verify_session_token(token) == "admin"


def test_tampered_session_token_rejected():
    # Flipping a character in the middle (the signature segment), not the
    # very last character - base64url's trailing bits can be padding that
    # doesn't affect the decoded value, which made this test flaky (a
    # "tampered" token could coincidentally decode identically).
    token = auth.create_session_token("admin")
    mid = len(token) // 2
    tampered = token[:mid] + ("a" if token[mid] != "a" else "b") + token[mid + 1:]
    assert auth.verify_session_token(tampered) is None


def test_forged_payload_rejected():
    """Swap in a different (validly-encoded) payload segment without the
    matching signature - confirms the signature is actually checked
    against the payload, not just present."""
    legit_token = auth.create_session_token("admin")
    forged_token = auth.create_session_token("attacker")
    payload_segment, _, signature_segment = forged_token.rpartition(".")
    _, _, legit_signature = legit_token.rpartition(".")
    franken_token = f"{payload_segment}.{legit_signature}"
    assert auth.verify_session_token(franken_token) is None


def test_none_token_rejected():
    assert auth.verify_session_token(None) is None


def test_empty_token_rejected():
    assert auth.verify_session_token("") is None


def test_expired_session_token_rejected(monkeypatch):
    monkeypatch.setattr(auth, "SESSION_MAX_AGE_SECONDS", 0)
    token = auth.create_session_token("admin")
    import time
    time.sleep(1.1)
    assert auth.verify_session_token(token) is None


def test_login_rate_limit_blocks_after_threshold():
    ip = "203.0.113.50"
    for _ in range(auth.LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        assert auth.login_rate_limited(ip) is False
    assert auth.login_rate_limited(ip) is True


def test_login_rate_limit_reset_on_success():
    ip = "203.0.113.51"
    for _ in range(auth.LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        auth.login_rate_limited(ip)
    auth.reset_rate_limit(ip)
    assert auth.login_rate_limited(ip) is False


def test_missing_secret_key_raises(monkeypatch):
    monkeypatch.delenv("TRACKER_SECRET_KEY", raising=False)
    import importlib
    importlib.reload(auth)
    try:
        with __import__("pytest").raises(RuntimeError):
            auth.create_session_token("admin")
    finally:
        os.environ["TRACKER_SECRET_KEY"] = "test-secret-key-not-for-production"
        importlib.reload(auth)
