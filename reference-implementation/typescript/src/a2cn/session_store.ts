/**
 * SessionStore - pluggable session persistence interface for A2CN.
 *
 * The reference implementation ships InMemorySessionStore as the default.
 * For production deployments where sessions span hours or days across
 * process restarts, implement SessionStore with a durable backend.
 *
 * Production backends are optional. Provide the backend client used by your
 * deployment, then pass the store instance to configureResponder(...,
 * sessionStore: store).
 */

import type { Dict } from "./messages.js";

/**
 * Abstract interface for A2CN session persistence.
 *
 * Implement this interface to use any durable session backend.
 * The interface is intentionally minimal: get, save, list, delete.
 * Additional methods (search, filter, expire) belong in the
 * implementing class, not this interface.
 */
export interface SessionStore {
  /** Retrieve session data by session_id. Returns null if session does not exist. */
  get(sessionId: string): Dict | null;

  /**
   * Persist session data. Overwrites existing data for the same
   * session_id. Implementations should be idempotent.
   */
  save(sessionId: string, sessionData: Dict): void;

  /** Return list of all active session_ids in the store. */
  listActive(): string[];

  /** Delete a session by session_id. No-op if session does not exist. */
  delete(sessionId: string): void;
}

/**
 * Default in-memory session store for development and testing.
 *
 * WARNING: All session state is lost on process restart.
 * A2CN sessions in enterprise procurement may span hours or days.
 * Use a persistent backend (Redis, PostgreSQL) for production.
 */
export class InMemorySessionStore implements SessionStore {
  private _store: Record<string, Dict> = {};

  get(sessionId: string): Dict | null {
    return this._store[sessionId] ?? null;
  }

  save(sessionId: string, sessionData: Dict): void {
    this._store[sessionId] = sessionData;
  }

  listActive(): string[] {
    return Object.keys(this._store);
  }

  delete(sessionId: string): void {
    delete this._store[sessionId];
  }
}

/** Minimal synchronous Redis-like client surface used by RedisSessionStore. */
export interface RedisLikeClient {
  get(key: string): string | Buffer | null;
  set(key: string, value: string, options?: { ex?: number }): void;
  scanIter(pattern: string): Iterable<string | Buffer>;
  delete(key: string): void;
}

/**
 * Redis-backed session store for production single-instance or small-cluster
 * deployments.
 *
 * The constructor accepts an already configured Redis-like client so callers
 * can own TLS, auth, sentinel, cluster, and connection-pool settings.
 */
export class RedisSessionStore implements SessionStore {
  redis: RedisLikeClient;
  keyPrefix: string;
  ttlSeconds: number | null;

  constructor(
    redisClient: RedisLikeClient,
    options: { keyPrefix?: string; ttlSeconds?: number | null } = {},
  ) {
    this.redis = redisClient;
    this.keyPrefix = options.keyPrefix ?? "a2cn:session:";
    this.ttlSeconds = options.ttlSeconds === undefined ? 60 * 60 * 24 * 30 : options.ttlSeconds;
  }

  private key(sessionId: string): string {
    return `${this.keyPrefix}${sessionId}`;
  }

  get(sessionId: string): Dict | null {
    let data = this.redis.get(this.key(sessionId));
    if (data === null || data === undefined) {
      return null;
    }
    if (Buffer.isBuffer(data)) {
      data = data.toString("utf-8");
    }
    return JSON.parse(data as string) as Dict;
  }

  save(sessionId: string, sessionData: Dict): void {
    const payload = sortedCompactJson(sessionData);
    const key = this.key(sessionId);
    if (this.ttlSeconds === null) {
      this.redis.set(key, payload);
    } else {
      this.redis.set(key, payload, { ex: this.ttlSeconds });
    }
  }

  listActive(): string[] {
    const prefixLen = this.keyPrefix.length;
    const sessionIds: string[] = [];
    for (let key of this.redis.scanIter(`${this.keyPrefix}*`)) {
      if (Buffer.isBuffer(key)) {
        key = key.toString("utf-8");
      }
      sessionIds.push((key as string).slice(prefixLen));
    }
    return sessionIds;
  }

  delete(sessionId: string): void {
    this.redis.delete(this.key(sessionId));
  }
}

/** Minimal DB-API-style connection surface used by PostgreSQLSessionStore. */
export interface PostgresLikeConnection {
  execute(sql: string, params?: unknown[]): {
    fetchone(): unknown[] | Record<string, unknown> | null;
    fetchall(): Array<unknown[] | Record<string, unknown>>;
  };
  commit?(): void;
}

/**
 * PostgreSQL-backed session store for deployments that require durable,
 * transactional persistence.
 *
 * The constructor accepts a DB-API-style connection object. Callers own
 * connection pooling and transaction policy; this class commits writes when
 * the connection exposes commit().
 */
export class PostgreSQLSessionStore implements SessionStore {
  connection: PostgresLikeConnection;
  tableName: string;

  constructor(connection: PostgresLikeConnection, options: { tableName?: string } = {}) {
    const tableName = options.tableName ?? "a2cn_sessions";
    if (
      !tableName ||
      !/^[A-Za-z]/.test(tableName) ||
      !/^[A-Za-z0-9_]+$/.test(tableName)
    ) {
      throw new Error(
        "table_name must start with a letter and contain only letters, numbers, and underscores",
      );
    }
    this.connection = connection;
    this.tableName = tableName;
  }

  /** Create the backing table if it does not already exist. */
  initializeSchema(): void {
    this.connection.execute(
      `
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
          session_id TEXT PRIMARY KEY,
          session_data JSONB NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
      `,
    );
    this.commit();
  }

  get(sessionId: string): Dict | null {
    const cursor = this.connection.execute(
      `SELECT session_data FROM ${this.tableName} WHERE session_id = %s`,
      [sessionId],
    );
    const row = cursor.fetchone();
    if (row === null || row === undefined) {
      return null;
    }
    const data = Array.isArray(row) ? row[0] : (row as Record<string, unknown>).session_data;
    if (typeof data === "string") {
      return JSON.parse(data) as Dict;
    }
    return data as Dict;
  }

  save(sessionId: string, sessionData: Dict): void {
    const payload = sortedCompactJson(sessionData);
    this.connection.execute(
      `
      INSERT INTO ${this.tableName} (session_id, session_data, updated_at)
      VALUES (%s, %s::jsonb, NOW())
      ON CONFLICT (session_id)
      DO UPDATE SET session_data = EXCLUDED.session_data, updated_at = NOW()
      `,
      [sessionId, payload],
    );
    this.commit();
  }

  listActive(): string[] {
    const cursor = this.connection.execute(
      `SELECT session_id FROM ${this.tableName} ORDER BY session_id`,
    );
    return cursor
      .fetchall()
      .map((row) =>
        Array.isArray(row) ? (row[0] as string) : ((row as Record<string, unknown>).session_id as string),
      );
  }

  delete(sessionId: string): void {
    this.connection.execute(`DELETE FROM ${this.tableName} WHERE session_id = %s`, [sessionId]);
    this.commit();
  }

  private commit(): void {
    if (typeof this.connection.commit === "function") {
      this.connection.commit();
    }
  }
}

/** JSON with sorted keys and no whitespace (mirror of Python json.dumps sort_keys/compact). */
function sortedCompactJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
