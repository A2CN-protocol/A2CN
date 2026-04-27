"""
SessionStore — pluggable session persistence interface for A2CN.

The reference implementation ships InMemorySessionStore as the default.
For production deployments where sessions span hours or days across
process restarts, implement SessionStore with a durable backend.

Production implementation example (Redis):

    import json
    import redis
    from session_store import SessionStore

    class RedisSessionStore(SessionStore):
        def __init__(self, redis_client: redis.Redis):
            self.redis = redis_client

        def get(self, session_id: str) -> dict | None:
            data = self.redis.get(f"a2cn:session:{session_id}")
            return json.loads(data) if data else None

        def save(self, session_id: str, session_data: dict) -> None:
            self.redis.set(
                f"a2cn:session:{session_id}",
                json.dumps(session_data),
                ex=86400 * 30  # 30-day TTL
            )

        def list_active(self) -> list[str]:
            return [
                k.decode().replace("a2cn:session:", "")
                for k in self.redis.scan_iter("a2cn:session:*")
            ]

        def delete(self, session_id: str) -> None:
            self.redis.delete(f"a2cn:session:{session_id}")
"""

from abc import ABC, abstractmethod


class SessionStore(ABC):
    """
    Abstract interface for A2CN session persistence.

    Implement this interface to use any durable session backend.
    The interface is intentionally minimal — get, save, list, delete.
    Additional methods (search, filter, expire) belong in the
    implementing class, not this interface.
    """

    @abstractmethod
    def get(self, session_id: str) -> dict | None:
        """
        Retrieve session data by session_id.
        Returns None if session does not exist.
        """
        ...

    @abstractmethod
    def save(self, session_id: str, session_data: dict) -> None:
        """
        Persist session data. Overwrites existing data for the same
        session_id. Implementations should be idempotent.
        """
        ...

    @abstractmethod
    def list_active(self) -> list[str]:
        """
        Return list of all active session_ids in the store.
        """
        ...

    @abstractmethod
    def delete(self, session_id: str) -> None:
        """
        Delete a session by session_id.
        No-op if session does not exist.
        """
        ...


class InMemorySessionStore(SessionStore):
    """
    Default in-memory session store for development and testing.

    WARNING: All session state is lost on process restart.
    A2CN sessions in enterprise procurement may span hours or days.
    Use a persistent backend (Redis, PostgreSQL) for production.
    """

    def __init__(self):
        self._store: dict[str, dict] = {}

    def get(self, session_id: str) -> dict | None:
        return self._store.get(session_id)

    def save(self, session_id: str, session_data: dict) -> None:
        self._store[session_id] = session_data

    def list_active(self) -> list[str]:
        return list(self._store.keys())

    def delete(self, session_id: str) -> None:
        self._store.pop(session_id, None)
