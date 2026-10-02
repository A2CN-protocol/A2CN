"""The protocol versions this library implements.

Every value is read from the module that owns it, never retyped here, so the
matrix cannot drift from the code that emits and verifies. The package's own
version (``a2cn.__version__``) is separate: it is the library's semver and moves
independently of the protocol versions a release implements.
"""

from a2cn.evidence import (
    RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
    SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
)
from a2cn.messages import PROTOCOL_ACT_VERSION
from a2cn.record import (
    ACCEPTED_TRANSACTION_RECORD_VERSIONS,
    KNOWN_TRANSACTION_RECORD_VERSIONS,
)

PROTOCOL_VERSIONS = {
    "wire": PROTOCOL_ACT_VERSION,
    "transaction_record": {
        "emits": ACCEPTED_TRANSACTION_RECORD_VERSIONS[-1],
        "accepts": list(ACCEPTED_TRANSACTION_RECORD_VERSIONS),
        "recognizes": list(KNOWN_TRANSACTION_RECORD_VERSIONS),
    },
    "session_evidence_record": {
        "emits": SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
        "recognizes": list(RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS),
    },
}
