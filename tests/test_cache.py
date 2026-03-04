"""Tests for the TokenCache."""

from concurrent.futures import ThreadPoolExecutor

from scrubjay.core.cache import TokenCache
from scrubjay.core.tokenizer import Tokenizer
from scrubjay.core.types import FieldType


class TestBasicOperations:
    def test_get_or_create_and_restore(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        token = cache.get_or_create("jsmith", FieldType.USERNAME, "actor.id", tok)
        assert token.startswith("USER-")
        assert cache.restore(token) == "jsmith"

    def test_get_or_create_reuses_existing(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        t1 = cache.get_or_create("jsmith", FieldType.USERNAME, "f1", tok)
        t2 = cache.get_or_create("jsmith", FieldType.USERNAME, "f2", tok)
        assert t1 == t2

    def test_restore_unknown_returns_none(self):
        cache = TokenCache()
        assert cache.restore("UNKNOWN-9999") is None

    def test_len(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        assert len(cache) == 0
        cache.get_or_create("a", FieldType.USERNAME, "f", tok)
        assert len(cache) == 1
        cache.get_or_create("b", FieldType.EMAIL, "f", tok)
        assert len(cache) == 2


class TestRestoreText:
    def test_basic_restore(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        token = cache.get_or_create("jsmith", FieldType.USERNAME, "f", tok)
        text = f"The user {token} logged in."
        restored = cache.restore_text(text)
        assert "jsmith" in restored
        assert token not in restored

    def test_longest_match_first(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        # Create username and email tokens
        user_token = cache.get_or_create("jsmith", FieldType.USERNAME, "f1", tok)
        email_token = cache.get_or_create("jsmith@company.com", FieldType.EMAIL, "f2", tok)
        # The email token contains the user token as a substring
        text = f"Email: {email_token}, User: {user_token}"
        restored = cache.restore_text(text)
        assert "jsmith@company.com" in restored
        assert "jsmith" in restored
        # Verify the email was restored properly (not partially replaced)
        assert email_token not in restored
        assert user_token not in restored


class TestStats:
    def test_stats_tracking(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        cache.get_or_create("a@b.com", FieldType.EMAIL, "f", tok)
        cache.get_or_create("c@d.com", FieldType.EMAIL, "f", tok)
        cache.get_or_create("user1", FieldType.USERNAME, "f", tok)
        stats = cache.stats()
        assert stats["EMAIL"] == 2
        assert stats["USERNAME"] == 1

    def test_stats_after_clear(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        cache.get_or_create("x", FieldType.USERNAME, "f", tok)
        cache.clear()
        assert cache.stats() == {}


class TestExport:
    def test_export_complete(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        cache.get_or_create("jsmith", FieldType.USERNAME, "actor.id", tok)
        exported = cache.export()
        assert "jsmith" in exported
        assert exported["jsmith"]["type"] == "USERNAME"
        assert exported["jsmith"]["first_seen_field"] == "actor.id"
        assert exported["jsmith"]["token"].startswith("USER-")


class TestClear:
    def test_clear_destroys_everything(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")
        token = cache.get_or_create("jsmith", FieldType.USERNAME, "f", tok)
        cache.clear()
        assert len(cache) == 0
        assert cache.restore(token) is None
        assert cache.stats() == {}


class TestThreadSafety:
    def test_concurrent_access(self):
        cache = TokenCache()
        tok = Tokenizer(seed="test")

        def create_entry(i: int) -> str:
            return cache.get_or_create(
                f"user{i}@example.com", FieldType.EMAIL, "email", tok
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(create_entry, range(100)))

        # All 100 should be unique
        assert len(set(results)) == 100
        assert len(cache) == 100

        # Each should be restorable
        for i, token in enumerate(results):
            assert cache.restore(token) == f"user{i}@example.com"
