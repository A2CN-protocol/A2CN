/**
 * The protocol versions this library implements.
 *
 * Every value is read from the module that owns it, never retyped here, so the
 * matrix cannot drift from the code that emits and verifies. The package's own
 * version (package.json) is separate: it is the library's semver and moves
 * independently of the protocol versions a release implements.
 */

import {
  RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
  SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
} from "./evidence.js";
import { PROTOCOL_ACT_VERSION } from "./messages.js";
import {
  ACCEPTED_TRANSACTION_RECORD_VERSIONS,
  KNOWN_TRANSACTION_RECORD_VERSIONS,
} from "./record.js";

export const PROTOCOL_VERSIONS = {
  wire: PROTOCOL_ACT_VERSION,
  transaction_record: {
    emits: ACCEPTED_TRANSACTION_RECORD_VERSIONS[ACCEPTED_TRANSACTION_RECORD_VERSIONS.length - 1],
    accepts: [...ACCEPTED_TRANSACTION_RECORD_VERSIONS],
    recognizes: [...KNOWN_TRANSACTION_RECORD_VERSIONS],
  },
  session_evidence_record: {
    emits: SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
    recognizes: [...RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS],
  },
} as const;
