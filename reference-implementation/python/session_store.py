"""Compatibility shim for imports that predate a2cn.session_store."""

from a2cn.session_store import InMemorySessionStore, SessionStore

__all__ = ["InMemorySessionStore", "SessionStore"]
