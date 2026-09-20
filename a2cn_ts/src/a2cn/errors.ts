/**
 * The protocol error, and the timestamp it stamps itself with.
 *
 * This lives apart from `session.ts` for one reason: the modules that sit
 * *below* the state machine need to raise a protocol error too, and importing
 * the state machine to get one would be a cycle. `line_items.ts` is the first
 * such module — a vendor amount it cannot convert is a protocol-level refusal,
 * not an implementation crash, so it throws `A2CNError` like everything else
 * rather than letting a bare `Error` escape to a caller who has no idea what to
 * do with it.
 *
 * `session.ts` imports both names and re-exports them, so
 * `import { A2CNError } from "./session.js"` keeps working for every existing
 * caller.
 *
 * The Python mirror is `reference-implementation/python/a2cn/errors.py`.
 */

import type { Dict } from "./messages.js";

/** Protocol error with A2CN error code, HTTP status, and context. */
export class A2CNError extends Error {
  code: string;
  httpStatus: number;
  detail: string;
  sessionId: string | null;
  messageId: string | null;

  constructor(
    code: string,
    message: string,
    httpStatus = 400,
    options: { detail?: string; sessionId?: string | null; messageId?: string | null } = {},
  ) {
    super(message);
    this.name = "A2CNError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.detail = options.detail ?? "";
    this.sessionId = options.sessionId ?? null;
    this.messageId = options.messageId ?? null;
  }

  toDict(): Dict {
    return {
      error: {
        code: this.code,
        message: this.message,
        detail: this.detail,
        timestamp: now(),
        session_id: this.sessionId,
        message_id: this.messageId,
      },
    };
  }
}

export function now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
