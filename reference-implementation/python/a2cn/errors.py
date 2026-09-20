"""The protocol error, and the timestamp it stamps itself with.

This lives apart from ``a2cn.session`` for one reason: the modules that sit
*below* the state machine need to raise a protocol error too, and importing the
state machine to get one would be a cycle. ``a2cn.line_items`` is the first such
module — a vendor amount it cannot convert is a protocol-level refusal, not an
implementation crash, so it raises ``A2CNError`` like everything else rather
than letting a bare ``ValueError`` escape to a caller who has no idea what to do
with it.

``a2cn.session`` imports both names and re-exports them, so
``from a2cn.session import A2CNError`` keeps working for every existing caller.

The TypeScript mirror is ``a2cn_ts/src/a2cn/errors.ts``.
"""

from __future__ import annotations

from datetime import datetime, timezone


class A2CNError(Exception):
    """Protocol error with A2CN error code, HTTP status, and context."""

    def __init__(
        self,
        code: str,
        message: str,
        http_status: int = 400,
        detail: str = "",
        session_id: str | None = None,
        message_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.detail = detail
        self.session_id = session_id
        self.message_id = message_id

    def to_dict(self) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
                "timestamp": _now(),
                "session_id": self.session_id,
                "message_id": self.message_id,
            }
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
