"""Tests for SessionStore interface and InMemorySessionStore implementation."""

from __future__ import annotations

import pytest
from session_store import (
    InMemorySessionStore,
    PostgreSQLSessionStore,
    RedisSessionStore,
    SessionStore,
)


class TestInMemorySessionStore:
    def test_save_and_get_returns_same_data(self):
        store = InMemorySessionStore()
        data = {"post_commitment_status": "CLOSED", "delivery_notice": {"message_id": "msg-1"}}
        store.save("sess-abc", data)
        result = store.get("sess-abc")
        assert result == data

    def test_get_returns_none_for_unknown_session(self):
        store = InMemorySessionStore()
        assert store.get("unknown-session-id") is None

    def test_list_active_returns_saved_session_ids(self):
        store = InMemorySessionStore()
        store.save("sess-1", {"status": "A"})
        store.save("sess-2", {"status": "B"})
        store.save("sess-3", {"status": "C"})
        active = store.list_active()
        assert set(active) == {"sess-1", "sess-2", "sess-3"}

    def test_list_active_empty_on_new_store(self):
        store = InMemorySessionStore()
        assert store.list_active() == []

    def test_delete_removes_session(self):
        store = InMemorySessionStore()
        store.save("sess-del", {"x": 1})
        store.delete("sess-del")
        assert store.get("sess-del") is None

    def test_delete_on_unknown_session_does_not_raise(self):
        store = InMemorySessionStore()
        store.delete("does-not-exist")  # should not raise

    def test_save_overwrites_existing_data(self):
        store = InMemorySessionStore()
        store.save("sess-overwrite", {"v": 1})
        store.save("sess-overwrite", {"v": 2})
        assert store.get("sess-overwrite") == {"v": 2}

    def test_list_active_excludes_deleted_sessions(self):
        store = InMemorySessionStore()
        store.save("sess-keep", {})
        store.save("sess-remove", {})
        store.delete("sess-remove")
        active = store.list_active()
        assert "sess-keep" in active
        assert "sess-remove" not in active

    def test_is_instance_of_session_store_abc(self):
        store = InMemorySessionStore()
        assert isinstance(store, SessionStore)

    def test_session_store_is_abstract(self):
        with pytest.raises(TypeError):
            SessionStore()  # cannot instantiate abstract class


class FakeRedis:
    def __init__(self):
        self.data = {}
        self.ttls = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value, ex=None):
        self.data[key] = value
        self.ttls[key] = ex

    def scan_iter(self, pattern):
        prefix = pattern.removesuffix("*")
        return [key.encode("utf-8") for key in self.data if key.startswith(prefix)]

    def delete(self, key):
        self.data.pop(key, None)


class TestRedisSessionStore:
    def test_save_get_and_ttl(self):
        redis = FakeRedis()
        store = RedisSessionStore(redis, ttl_seconds=60)

        store.save("sess-1", {"status": "CLOSED"})

        assert store.get("sess-1") == {"status": "CLOSED"}
        assert redis.ttls["a2cn:session:sess-1"] == 60

    def test_list_active_strips_prefix(self):
        redis = FakeRedis()
        store = RedisSessionStore(redis)
        store.save("sess-b", {"status": "B"})
        store.save("sess-a", {"status": "A"})

        assert set(store.list_active()) == {"sess-a", "sess-b"}

    def test_delete_removes_key(self):
        redis = FakeRedis()
        store = RedisSessionStore(redis)
        store.save("sess-del", {"status": "A"})
        store.delete("sess-del")

        assert store.get("sess-del") is None

    def test_save_without_ttl(self):
        redis = FakeRedis()
        store = RedisSessionStore(redis, ttl_seconds=None)
        store.save("sess-no-ttl", {"status": "A"})

        assert redis.ttls["a2cn:session:sess-no-ttl"] is None


class FakeCursor:
    def __init__(self, rows=None):
        self._rows = rows or []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class FakePostgresConnection:
    def __init__(self):
        self.data = {}
        self.statements = []
        self.commits = 0

    def execute(self, query, params=None):
        self.statements.append((query, params))
        normalized = " ".join(query.split()).upper()
        if normalized.startswith("CREATE TABLE"):
            return FakeCursor()
        if normalized.startswith("SELECT SESSION_DATA"):
            session_id = params[0]
            if session_id not in self.data:
                return FakeCursor()
            return FakeCursor([(self.data[session_id],)])
        if normalized.startswith("INSERT INTO"):
            session_id, payload = params
            self.data[session_id] = payload
            return FakeCursor()
        if normalized.startswith("SELECT SESSION_ID"):
            return FakeCursor([(session_id,) for session_id in sorted(self.data)])
        if normalized.startswith("DELETE FROM"):
            self.data.pop(params[0], None)
            return FakeCursor()
        raise AssertionError(f"unexpected query: {query}")

    def commit(self):
        self.commits += 1


class TestPostgreSQLSessionStore:
    def test_table_name_validation(self):
        with pytest.raises(ValueError, match="table_name"):
            PostgreSQLSessionStore(FakePostgresConnection(), table_name="sessions;drop")

    def test_initialize_schema_commits(self):
        conn = FakePostgresConnection()
        store = PostgreSQLSessionStore(conn)

        store.initialize_schema()

        assert "CREATE TABLE" in conn.statements[0][0]
        assert conn.commits == 1

    def test_save_get_list_and_delete(self):
        conn = FakePostgresConnection()
        store = PostgreSQLSessionStore(conn)

        store.save("sess-2", {"status": "B"})
        store.save("sess-1", {"status": "A"})

        assert store.get("sess-1") == {"status": "A"}
        assert store.list_active() == ["sess-1", "sess-2"]

        store.delete("sess-1")

        assert store.get("sess-1") is None
        assert store.list_active() == ["sess-2"]
        assert conn.commits == 3
