"""Tests for SessionStore interface and InMemorySessionStore implementation."""

from __future__ import annotations

import pytest
from a2cn.session_store import InMemorySessionStore, SessionStore


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
