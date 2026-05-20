"""
SessionStore — pluggable session persistence interface for A2CN.

The reference implementation ships InMemorySessionStore as the default.
For production deployments where sessions span hours or days across
process restarts, implement SessionStore with a durable backend.

Production backends are optional. Install the backend driver used by your
deployment, then pass the store instance to configure_responder(...,
session_store=store).
"""

from abc import ABC, abstractmethod
import json
from typing import Any


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


class RedisSessionStore(SessionStore):
    """
    Redis-backed session store for production single-instance or small-cluster
    deployments.

    The constructor accepts an already configured redis-py client so callers can
    own TLS, auth, sentinel, cluster, and connection-pool settings.
    """

    def __init__(
        self,
        redis_client: Any,
        *,
        key_prefix: str = "a2cn:session:",
        ttl_seconds: int | None = 60 * 60 * 24 * 30,
    ) -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.ttl_seconds = ttl_seconds

    def _key(self, session_id: str) -> str:
        return f"{self.key_prefix}{session_id}"

    def get(self, session_id: str) -> dict | None:
        data = self.redis.get(self._key(session_id))
        if data is None:
            return None
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)

    def save(self, session_id: str, session_data: dict) -> None:
        payload = json.dumps(session_data, separators=(",", ":"), sort_keys=True)
        key = self._key(session_id)
        if self.ttl_seconds is None:
            self.redis.set(key, payload)
        else:
            self.redis.set(key, payload, ex=self.ttl_seconds)

    def list_active(self) -> list[str]:
        prefix_len = len(self.key_prefix)
        session_ids: list[str] = []
        for key in self.redis.scan_iter(f"{self.key_prefix}*"):
            if isinstance(key, bytes):
                key = key.decode("utf-8")
            session_ids.append(key[prefix_len:])
        return session_ids

    def delete(self, session_id: str) -> None:
        self.redis.delete(self._key(session_id))


class PostgreSQLSessionStore(SessionStore):
    """
    PostgreSQL-backed session store for deployments that require durable,
    transactional persistence.

    The constructor accepts a DB-API/psycopg-style connection object. Callers own
    connection pooling and transaction policy; this class commits writes when the
    connection exposes commit().
    """

    def __init__(self, connection: Any, *, table_name: str = "a2cn_sessions") -> None:
        if (
            not table_name
            or not table_name[0].isalpha()
            or not table_name.replace("_", "").isalnum()
        ):
            raise ValueError(
                "table_name must start with a letter and contain only letters, numbers, and underscores"
            )
        self.connection = connection
        self.table_name = table_name

    def initialize_schema(self) -> None:
        """Create the backing table if it does not already exist."""
        self.connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                session_id TEXT PRIMARY KEY,
                session_data JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        self._commit()

    def get(self, session_id: str) -> dict | None:
        cursor = self.connection.execute(
            f"SELECT session_data FROM {self.table_name} WHERE session_id = %s",
            (session_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        data = row[0] if isinstance(row, tuple) else row["session_data"]
        if isinstance(data, str):
            return json.loads(data)
        return data

    def save(self, session_id: str, session_data: dict) -> None:
        payload = json.dumps(session_data, separators=(",", ":"), sort_keys=True)
        self.connection.execute(
            f"""
            INSERT INTO {self.table_name} (session_id, session_data, updated_at)
            VALUES (%s, %s::jsonb, NOW())
            ON CONFLICT (session_id)
            DO UPDATE SET session_data = EXCLUDED.session_data, updated_at = NOW()
            """,
            (session_id, payload),
        )
        self._commit()

    def list_active(self) -> list[str]:
        cursor = self.connection.execute(
            f"SELECT session_id FROM {self.table_name} ORDER BY session_id"
        )
        return [
            row[0] if isinstance(row, tuple) else row["session_id"]
            for row in cursor.fetchall()
        ]

    def delete(self, session_id: str) -> None:
        self.connection.execute(
            f"DELETE FROM {self.table_name} WHERE session_id = %s",
            (session_id,),
        )
        self._commit()

    def _commit(self) -> None:
        commit = getattr(self.connection, "commit", None)
        if commit is not None:
            commit()
