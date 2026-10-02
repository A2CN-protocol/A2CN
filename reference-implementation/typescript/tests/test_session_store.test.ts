/** Tests for SessionStore interface and InMemorySessionStore implementation. */

import { describe, expect, test } from "vitest";

import * as sessionStoreModule from "../src/a2cn/session_store.js";
import {
  InMemorySessionStore,
  PostgreSQLSessionStore,
  RedisSessionStore,
  type PostgresLikeConnection,
  type RedisLikeClient,
} from "../src/a2cn/session_store.js";

describe("InMemorySessionStore", () => {
  test("save and get returns same data", () => {
    const store = new InMemorySessionStore();
    const data = { post_commitment_status: "CLOSED", delivery_notice: { message_id: "msg-1" } };
    store.save("sess-abc", data);
    const result = store.get("sess-abc");
    expect(result).toEqual(data);
  });

  test("get returns null for unknown session", () => {
    const store = new InMemorySessionStore();
    expect(store.get("unknown-session-id")).toBeNull();
  });

  test("list active returns saved session ids", () => {
    const store = new InMemorySessionStore();
    store.save("sess-1", { status: "A" });
    store.save("sess-2", { status: "B" });
    store.save("sess-3", { status: "C" });
    const active = store.listActive();
    expect(new Set(active)).toEqual(new Set(["sess-1", "sess-2", "sess-3"]));
  });

  test("list active empty on new store", () => {
    const store = new InMemorySessionStore();
    expect(store.listActive()).toEqual([]);
  });

  test("delete removes session", () => {
    const store = new InMemorySessionStore();
    store.save("sess-del", { x: 1 });
    store.delete("sess-del");
    expect(store.get("sess-del")).toBeNull();
  });

  test("delete on unknown session does not raise", () => {
    const store = new InMemorySessionStore();
    store.delete("does-not-exist"); // should not throw
  });

  test("save overwrites existing data", () => {
    const store = new InMemorySessionStore();
    store.save("sess-overwrite", { v: 1 });
    store.save("sess-overwrite", { v: 2 });
    expect(store.get("sess-overwrite")).toEqual({ v: 2 });
  });

  test("list active excludes deleted sessions", () => {
    const store = new InMemorySessionStore();
    store.save("sess-keep", {});
    store.save("sess-remove", {});
    store.delete("sess-remove");
    const active = store.listActive();
    expect(active).toContain("sess-keep");
    expect(active).not.toContain("sess-remove");
  });

  test("implements the session store interface", () => {
    // Structural analogue of Python's isinstance(store, SessionStore) ABC check.
    const store = new InMemorySessionStore();
    expect(typeof store.get).toBe("function");
    expect(typeof store.save).toBe("function");
    expect(typeof store.listActive).toBe("function");
    expect(typeof store.delete).toBe("function");
  });

  test("session store is abstract", () => {
    // The SessionStore interface has no runtime constructor — the analogue of
    // Python's "cannot instantiate abstract class".
    expect((sessionStoreModule as Record<string, unknown>).SessionStore).toBeUndefined();
  });
});

class FakeRedis implements RedisLikeClient {
  data: Record<string, string> = {};
  ttls: Record<string, number | null> = {};

  get(key: string): string | null {
    return this.data[key] ?? null;
  }

  set(key: string, value: string, options?: { ex?: number }): void {
    this.data[key] = value;
    this.ttls[key] = options?.ex ?? null;
  }

  scanIter(pattern: string): Iterable<string | Buffer> {
    const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
    return Object.keys(this.data)
      .filter((key) => key.startsWith(prefix))
      .map((key) => Buffer.from(key, "utf-8"));
  }

  delete(key: string): void {
    delete this.data[key];
  }
}

describe("RedisSessionStore", () => {
  test("save get and ttl", () => {
    const redis = new FakeRedis();
    const store = new RedisSessionStore(redis, { ttlSeconds: 60 });

    store.save("sess-1", { status: "CLOSED" });

    expect(store.get("sess-1")).toEqual({ status: "CLOSED" });
    expect(redis.ttls["a2cn:session:sess-1"]).toBe(60);
  });

  test("list active strips prefix", () => {
    const redis = new FakeRedis();
    const store = new RedisSessionStore(redis);
    store.save("sess-b", { status: "B" });
    store.save("sess-a", { status: "A" });

    expect(new Set(store.listActive())).toEqual(new Set(["sess-a", "sess-b"]));
  });

  test("delete removes key", () => {
    const redis = new FakeRedis();
    const store = new RedisSessionStore(redis);
    store.save("sess-del", { status: "A" });
    store.delete("sess-del");

    expect(store.get("sess-del")).toBeNull();
  });

  test("save without ttl", () => {
    const redis = new FakeRedis();
    const store = new RedisSessionStore(redis, { ttlSeconds: null });
    store.save("sess-no-ttl", { status: "A" });

    expect(redis.ttls["a2cn:session:sess-no-ttl"]).toBeNull();
  });
});

class FakeCursor {
  private _rows: Array<unknown[]>;

  constructor(rows: Array<unknown[]> = []) {
    this._rows = rows;
  }

  fetchone(): unknown[] | null {
    return this._rows.length > 0 ? this._rows[0] : null;
  }

  fetchall(): Array<unknown[]> {
    return this._rows;
  }
}

class FakePostgresConnection implements PostgresLikeConnection {
  data: Record<string, string> = {};
  statements: Array<[string, unknown[] | undefined]> = [];
  commits = 0;

  execute(query: string, params?: unknown[]): FakeCursor {
    this.statements.push([query, params]);
    const normalized = query.split(/\s+/).join(" ").trim().toUpperCase();
    if (normalized.startsWith("CREATE TABLE")) {
      return new FakeCursor();
    }
    if (normalized.startsWith("SELECT SESSION_DATA")) {
      const sessionId = params![0] as string;
      if (!(sessionId in this.data)) {
        return new FakeCursor();
      }
      return new FakeCursor([[this.data[sessionId]]]);
    }
    if (normalized.startsWith("INSERT INTO")) {
      const [sessionId, payload] = params as [string, string];
      this.data[sessionId] = payload;
      return new FakeCursor();
    }
    if (normalized.startsWith("SELECT SESSION_ID")) {
      return new FakeCursor(Object.keys(this.data).sort().map((sessionId) => [sessionId]));
    }
    if (normalized.startsWith("DELETE FROM")) {
      delete this.data[params![0] as string];
      return new FakeCursor();
    }
    throw new Error(`unexpected query: ${query}`);
  }

  commit(): void {
    this.commits += 1;
  }
}

describe("PostgreSQLSessionStore", () => {
  test("table name validation", () => {
    expect(
      () => new PostgreSQLSessionStore(new FakePostgresConnection(), { tableName: "sessions;drop" }),
    ).toThrow(/table_name/);
    expect(
      () => new PostgreSQLSessionStore(new FakePostgresConnection(), { tableName: "1sessions" }),
    ).toThrow(/table_name/);
  });

  test("initialize schema commits", () => {
    const conn = new FakePostgresConnection();
    const store = new PostgreSQLSessionStore(conn);

    store.initializeSchema();

    expect(conn.statements[0][0]).toContain("CREATE TABLE");
    expect(conn.commits).toBe(1);
  });

  test("save get list and delete", () => {
    const conn = new FakePostgresConnection();
    const store = new PostgreSQLSessionStore(conn);

    store.save("sess-2", { status: "B" });
    store.save("sess-1", { status: "A" });

    expect(store.get("sess-1")).toEqual({ status: "A" });
    expect(store.listActive()).toEqual(["sess-1", "sess-2"]);

    store.delete("sess-1");

    expect(store.get("sess-1")).toBeNull();
    expect(store.listActive()).toEqual(["sess-2"]);
    expect(conn.commits).toBe(3);
  });
});
