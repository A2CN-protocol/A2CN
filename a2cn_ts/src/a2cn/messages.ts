/**
 * A2CN Message Classes
 *
 * All field names match the wire format exactly (Section 6–7 of the spec).
 * Every class has a toDict() method that serializes to wire format,
 * omitting null/undefined fields (optional fields that were not set).
 */

export type Dict = Record<string, unknown>;

/** Recursively remove null/undefined values from a dict. */
export function dropNone(d: Dict): Dict {
  const result: Dict = {};
  for (const [k, v] of Object.entries(d)) {
    if (v === null || v === undefined) {
      continue;
    }
    if (Array.isArray(v)) {
      result[k] = v.map((i) =>
        i !== null && typeof i === "object" && !Array.isArray(i) ? dropNone(i as Dict) : i,
      );
    } else if (typeof v === "object") {
      result[k] = dropNone(v as Dict);
    } else {
      result[k] = v;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Sub-objects
// ---------------------------------------------------------------------------

export class SessionParams {
  deal_type: string;
  currency: string;
  subject: string;
  max_rounds: number;
  session_timeout_seconds: number;
  round_timeout_seconds: number;
  subject_reference: string | null;
  estimated_value: number | null;
  impasse_threshold: number | null;

  constructor(props: {
    deal_type: string;
    currency: string;
    subject: string;
    max_rounds: number;
    session_timeout_seconds: number;
    round_timeout_seconds: number;
    subject_reference?: string | null;
    estimated_value?: number | null;
    impasse_threshold?: number | null;
  }) {
    this.deal_type = props.deal_type;
    this.currency = props.currency;
    this.subject = props.subject;
    this.max_rounds = props.max_rounds;
    this.session_timeout_seconds = props.session_timeout_seconds;
    this.round_timeout_seconds = props.round_timeout_seconds;
    this.subject_reference = props.subject_reference ?? null;
    this.estimated_value = props.estimated_value ?? null;
    this.impasse_threshold = props.impasse_threshold ?? null;
  }

  toDict(): Dict {
    return dropNone({
      deal_type: this.deal_type,
      currency: this.currency,
      subject: this.subject,
      subject_reference: this.subject_reference,
      estimated_value: this.estimated_value,
      max_rounds: this.max_rounds,
      session_timeout_seconds: this.session_timeout_seconds,
      round_timeout_seconds: this.round_timeout_seconds,
      impasse_threshold: this.impasse_threshold,
    });
  }
}

export class AgentInfo {
  organization_name: string;
  did: string;
  verification_method: string;
  agent_id: string;
  endpoint: string;

  constructor(props: {
    organization_name: string;
    did: string;
    verification_method: string;
    agent_id: string;
    endpoint: string;
  }) {
    this.organization_name = props.organization_name;
    this.did = props.did;
    this.verification_method = props.verification_method;
    this.agent_id = props.agent_id;
    this.endpoint = props.endpoint;
  }

  toDict(): Dict {
    return {
      organization_name: this.organization_name,
      did: this.did,
      verification_method: this.verification_method,
      agent_id: this.agent_id,
      endpoint: this.endpoint,
    };
  }
}

export class DeclaredMandate {
  mandate_type: string; // "declared"
  agent_id: string;
  principal_organization: string;
  principal_did: string;
  authorized_deal_types: string[];
  max_commitment_value: number;
  max_commitment_currency: string;
  valid_from: string;
  valid_until: string;
  scope_description: string | null;

  constructor(props: {
    mandate_type: string;
    agent_id: string;
    principal_organization: string;
    principal_did: string;
    authorized_deal_types: string[];
    max_commitment_value: number;
    max_commitment_currency: string;
    valid_from: string;
    valid_until: string;
    scope_description?: string | null;
  }) {
    this.mandate_type = props.mandate_type;
    this.agent_id = props.agent_id;
    this.principal_organization = props.principal_organization;
    this.principal_did = props.principal_did;
    this.authorized_deal_types = props.authorized_deal_types;
    this.max_commitment_value = props.max_commitment_value;
    this.max_commitment_currency = props.max_commitment_currency;
    this.valid_from = props.valid_from;
    this.valid_until = props.valid_until;
    this.scope_description = props.scope_description ?? null;
  }

  toDict(): Dict {
    return dropNone({
      mandate_type: this.mandate_type,
      agent_id: this.agent_id,
      principal_organization: this.principal_organization,
      principal_did: this.principal_did,
      authorized_deal_types: this.authorized_deal_types,
      max_commitment_value: this.max_commitment_value,
      max_commitment_currency: this.max_commitment_currency,
      valid_from: this.valid_from,
      valid_until: this.valid_until,
      scope_description: this.scope_description,
    });
  }
}

export class TermsObject {
  total_value: number;
  currency: string;
  line_items: Dict[] | null;
  payment_terms: Dict | null;
  delivery_terms: Dict | null;
  contract_duration: Dict | null;
  sla: Dict | null;
  custom_terms: Dict | null;

  constructor(props: {
    total_value: number;
    currency: string;
    line_items?: Dict[] | null;
    payment_terms?: Dict | null;
    delivery_terms?: Dict | null;
    contract_duration?: Dict | null;
    sla?: Dict | null;
    custom_terms?: Dict | null;
  }) {
    this.total_value = props.total_value;
    this.currency = props.currency;
    this.line_items = props.line_items ?? null;
    this.payment_terms = props.payment_terms ?? null;
    this.delivery_terms = props.delivery_terms ?? null;
    this.contract_duration = props.contract_duration ?? null;
    this.sla = props.sla ?? null;
    this.custom_terms = props.custom_terms ?? null;
  }

  toDict(): Dict {
    return dropNone({
      total_value: this.total_value,
      currency: this.currency,
      line_items: this.line_items,
      payment_terms: this.payment_terms,
      delivery_terms: this.delivery_terms,
      contract_duration: this.contract_duration,
      sla: this.sla,
      custom_terms: this.custom_terms,
    });
  }
}

function hasToDict(value: unknown): value is { toDict(): Dict } {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof (value as { toDict?: unknown }).toDict === "function"
  );
}

// ---------------------------------------------------------------------------
// Session Initiation
// ---------------------------------------------------------------------------

export class SessionInit {
  message_type: string; // "session_init"
  message_id: string;
  protocol_version: string; // "0.2"
  session_params: SessionParams;
  initiator: AgentInfo;
  initiator_mandate: DeclaredMandate | Dict;
  metadata: Dict | null;

  constructor(props: {
    message_type: string;
    message_id: string;
    protocol_version: string;
    session_params: SessionParams;
    initiator: AgentInfo;
    initiator_mandate: DeclaredMandate | Dict;
    metadata?: Dict | null;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.protocol_version = props.protocol_version;
    this.session_params = props.session_params;
    this.initiator = props.initiator;
    this.initiator_mandate = props.initiator_mandate;
    this.metadata = props.metadata ?? null;
  }

  toDict(): Dict {
    const mandate = hasToDict(this.initiator_mandate)
      ? this.initiator_mandate.toDict()
      : this.initiator_mandate;
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      protocol_version: this.protocol_version,
      session_params: this.session_params.toDict(),
      initiator: this.initiator.toDict(),
      initiator_mandate: mandate,
      metadata: this.metadata,
    });
  }
}

export class SessionAck {
  message_type: string; // "session_ack"
  message_id: string;
  session_id: string;
  in_reply_to: string;
  protocol_version: string; // "0.2"
  session_params_accepted: Dict;
  responder: AgentInfo;
  responder_mandate: DeclaredMandate | Dict;
  session_created_at: string;
  current_turn: string; // "initiator"

  constructor(props: {
    message_type: string;
    message_id: string;
    session_id: string;
    in_reply_to: string;
    protocol_version: string;
    session_params_accepted: Dict;
    responder: AgentInfo;
    responder_mandate: DeclaredMandate | Dict;
    session_created_at: string;
    current_turn: string;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.in_reply_to = props.in_reply_to;
    this.protocol_version = props.protocol_version;
    this.session_params_accepted = props.session_params_accepted;
    this.responder = props.responder;
    this.responder_mandate = props.responder_mandate;
    this.session_created_at = props.session_created_at;
    this.current_turn = props.current_turn;
  }

  toDict(): Dict {
    const mandate = hasToDict(this.responder_mandate)
      ? this.responder_mandate.toDict()
      : this.responder_mandate;
    return {
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      in_reply_to: this.in_reply_to,
      protocol_version: this.protocol_version,
      session_params_accepted: this.session_params_accepted,
      responder: this.responder.toDict(),
      responder_mandate: mandate,
      session_created_at: this.session_created_at,
      current_turn: this.current_turn,
    };
  }
}

export class SessionReject {
  message_type: string; // "session_reject"
  message_id: string;
  in_reply_to: string;
  error_code: string;
  error_message: string;
  retry_after_seconds: number | null;

  constructor(props: {
    message_type: string;
    message_id: string;
    in_reply_to: string;
    error_code: string;
    error_message: string;
    retry_after_seconds?: number | null;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.in_reply_to = props.in_reply_to;
    this.error_code = props.error_code;
    this.error_message = props.error_message;
    this.retry_after_seconds = props.retry_after_seconds ?? null;
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      in_reply_to: this.in_reply_to,
      error_code: this.error_code,
      error_message: this.error_message,
      retry_after_seconds: this.retry_after_seconds,
    });
  }
}

// ---------------------------------------------------------------------------
// Offer Exchange
// ---------------------------------------------------------------------------

/** Covers both 'offer' (round 1) and 'counteroffer' (round 2+). */
export class Offer {
  message_type: string; // "offer" | "counteroffer"
  message_id: string;
  session_id: string;
  round_number: number;
  sequence_number: number;
  sender_did: string;
  sender_agent_id: string;
  sender_verification_method: string;
  timestamp: string;
  expires_at: string;
  terms: TermsObject | Dict;
  protocol_act_hash: string;
  protocol_act_signature: string;
  in_reply_to: string | null; // absent in round 1

  constructor(props: {
    message_type: string;
    message_id: string;
    session_id: string;
    round_number: number;
    sequence_number: number;
    sender_did: string;
    sender_agent_id: string;
    sender_verification_method: string;
    timestamp: string;
    expires_at: string;
    terms: TermsObject | Dict;
    protocol_act_hash: string;
    protocol_act_signature: string;
    in_reply_to?: string | null;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.round_number = props.round_number;
    this.sequence_number = props.sequence_number;
    this.sender_did = props.sender_did;
    this.sender_agent_id = props.sender_agent_id;
    this.sender_verification_method = props.sender_verification_method;
    this.timestamp = props.timestamp;
    this.expires_at = props.expires_at;
    this.terms = props.terms;
    this.protocol_act_hash = props.protocol_act_hash;
    this.protocol_act_signature = props.protocol_act_signature;
    this.in_reply_to = props.in_reply_to ?? null;
  }

  toDict(): Dict {
    const termsDict = hasToDict(this.terms) ? this.terms.toDict() : this.terms;
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      in_reply_to: this.in_reply_to,
      round_number: this.round_number,
      sequence_number: this.sequence_number,
      sender_did: this.sender_did,
      sender_agent_id: this.sender_agent_id,
      sender_verification_method: this.sender_verification_method,
      timestamp: this.timestamp,
      expires_at: this.expires_at,
      terms: termsDict,
      protocol_act_hash: this.protocol_act_hash,
      protocol_act_signature: this.protocol_act_signature,
    });
  }

  /** Return the protocol act object used for signing (Section 7.3.1). */
  protocolActObject(): Dict {
    const termsDict = hasToDict(this.terms) ? this.terms.toDict() : this.terms;
    return {
      protocol_version: "0.2",
      session_id: this.session_id,
      round_number: this.round_number,
      sequence_number: this.sequence_number,
      message_type: this.message_type,
      sender_did: this.sender_did,
      timestamp: this.timestamp,
      expires_at: this.expires_at,
      terms: termsDict,
    };
  }
}

export class Acceptance {
  message_type: string; // "acceptance"
  message_id: string;
  session_id: string;
  in_reply_to: string;
  round_number: number;
  sequence_number: number;
  accepted_offer_id: string;
  accepted_protocol_act_hash: string;
  sender_did: string;
  sender_agent_id: string;
  sender_verification_method: string;
  timestamp: string;
  acceptance_signature: string;

  constructor(props: {
    message_type: string;
    message_id: string;
    session_id: string;
    in_reply_to: string;
    round_number: number;
    sequence_number: number;
    accepted_offer_id: string;
    accepted_protocol_act_hash: string;
    sender_did: string;
    sender_agent_id: string;
    sender_verification_method: string;
    timestamp: string;
    acceptance_signature: string;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.in_reply_to = props.in_reply_to;
    this.round_number = props.round_number;
    this.sequence_number = props.sequence_number;
    this.accepted_offer_id = props.accepted_offer_id;
    this.accepted_protocol_act_hash = props.accepted_protocol_act_hash;
    this.sender_did = props.sender_did;
    this.sender_agent_id = props.sender_agent_id;
    this.sender_verification_method = props.sender_verification_method;
    this.timestamp = props.timestamp;
    this.acceptance_signature = props.acceptance_signature;
  }

  toDict(): Dict {
    return {
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      in_reply_to: this.in_reply_to,
      round_number: this.round_number,
      sequence_number: this.sequence_number,
      accepted_offer_id: this.accepted_offer_id,
      accepted_protocol_act_hash: this.accepted_protocol_act_hash,
      sender_did: this.sender_did,
      sender_agent_id: this.sender_agent_id,
      sender_verification_method: this.sender_verification_method,
      timestamp: this.timestamp,
      acceptance_signature: this.acceptance_signature,
    };
  }

  /** The object signed to produce acceptance_signature (Section 7.4). */
  acceptancePayload(): Dict {
    return {
      session_id: this.session_id,
      round_number: this.round_number,
      sequence_number: this.sequence_number,
      accepted_offer_id: this.accepted_offer_id,
      accepted_protocol_act_hash: this.accepted_protocol_act_hash,
    };
  }
}

export class Rejection {
  message_type: string; // "rejection"
  message_id: string;
  session_id: string;
  in_reply_to: string;
  round_number: number;
  sequence_number: number;
  rejected_offer_id: string;
  sender_did: string;
  sender_agent_id: string;
  timestamp: string;
  reason_code: string;
  reason_description: string | null;

  constructor(props: {
    message_type: string;
    message_id: string;
    session_id: string;
    in_reply_to: string;
    round_number: number;
    sequence_number: number;
    rejected_offer_id: string;
    sender_did: string;
    sender_agent_id: string;
    timestamp: string;
    reason_code: string;
    reason_description?: string | null;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.in_reply_to = props.in_reply_to;
    this.round_number = props.round_number;
    this.sequence_number = props.sequence_number;
    this.rejected_offer_id = props.rejected_offer_id;
    this.sender_did = props.sender_did;
    this.sender_agent_id = props.sender_agent_id;
    this.timestamp = props.timestamp;
    this.reason_code = props.reason_code;
    this.reason_description = props.reason_description ?? null;
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      in_reply_to: this.in_reply_to,
      round_number: this.round_number,
      sequence_number: this.sequence_number,
      rejected_offer_id: this.rejected_offer_id,
      sender_did: this.sender_did,
      sender_agent_id: this.sender_agent_id,
      timestamp: this.timestamp,
      reason_code: this.reason_code,
      reason_description: this.reason_description,
    });
  }
}

export class Withdrawal {
  message_type: string; // "withdrawal"
  message_id: string;
  session_id: string;
  sequence_number: number;
  sender_did: string;
  sender_agent_id: string;
  timestamp: string;
  reason_code: string;
  in_reply_to: string | null;
  reason_description: string | null;

  constructor(props: {
    message_type: string;
    message_id: string;
    session_id: string;
    sequence_number: number;
    sender_did: string;
    sender_agent_id: string;
    timestamp: string;
    reason_code: string;
    in_reply_to?: string | null;
    reason_description?: string | null;
  }) {
    this.message_type = props.message_type;
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.sequence_number = props.sequence_number;
    this.sender_did = props.sender_did;
    this.sender_agent_id = props.sender_agent_id;
    this.timestamp = props.timestamp;
    this.reason_code = props.reason_code;
    this.in_reply_to = props.in_reply_to ?? null;
    this.reason_description = props.reason_description ?? null;
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      in_reply_to: this.in_reply_to,
      sequence_number: this.sequence_number,
      sender_did: this.sender_did,
      sender_agent_id: this.sender_agent_id,
      timestamp: this.timestamp,
      reason_code: this.reason_code,
      reason_description: this.reason_description,
    });
  }
}

// ---------------------------------------------------------------------------
// v0.2.0: Session Invitation (Component 8)
// ---------------------------------------------------------------------------

export const InvitationStatus = {
  PENDING: "pending",
  ACCEPTED: "accepted",
  DECLINED: "declined",
  EXPIRED: "expired",
} as const;

export type InvitationStatusValue = (typeof InvitationStatus)[keyof typeof InvitationStatus];

export class SessionInvitation {
  message_type: string; // always "session_invitation"
  invitation_id: string; // UUID v4
  a2cn_version: string; // "0.2"
  inviter_did: string;
  inviter_endpoint: string; // HTTPS URL of inviter's A2CN endpoint
  inviter_discovery_url: string;
  proposed_deal_type: string;
  proposed_session_params: Dict; // currency, max_rounds, timeouts
  proposed_terms_summary: Dict; // description, estimated_value, currency
  inviter_mandate_summary: Dict; // mandate_type, max_commitment_value, authorized_deal_types
  invitation_expires_at: string; // ISO 8601 UTC
  accept_endpoint: string; // HTTPS URL to POST acceptance to
  decline_endpoint: string; // HTTPS URL to POST decline to
  inviter_verification_method: string;
  invitation_signature: string; // set after signing; excluded from canonical form

  constructor(props: {
    message_type: string;
    invitation_id: string;
    a2cn_version: string;
    inviter_did: string;
    inviter_endpoint: string;
    inviter_discovery_url: string;
    proposed_deal_type: string;
    proposed_session_params: Dict;
    proposed_terms_summary: Dict;
    inviter_mandate_summary: Dict;
    invitation_expires_at: string;
    accept_endpoint: string;
    decline_endpoint: string;
    inviter_verification_method: string;
    invitation_signature?: string;
  }) {
    this.message_type = props.message_type;
    this.invitation_id = props.invitation_id;
    this.a2cn_version = props.a2cn_version;
    this.inviter_did = props.inviter_did;
    this.inviter_endpoint = props.inviter_endpoint;
    this.inviter_discovery_url = props.inviter_discovery_url;
    this.proposed_deal_type = props.proposed_deal_type;
    this.proposed_session_params = props.proposed_session_params;
    this.proposed_terms_summary = props.proposed_terms_summary;
    this.inviter_mandate_summary = props.inviter_mandate_summary;
    this.invitation_expires_at = props.invitation_expires_at;
    this.accept_endpoint = props.accept_endpoint;
    this.decline_endpoint = props.decline_endpoint;
    this.inviter_verification_method = props.inviter_verification_method;
    this.invitation_signature = props.invitation_signature ?? "";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      invitation_id: this.invitation_id,
      a2cn_version: this.a2cn_version,
      inviter_did: this.inviter_did,
      inviter_endpoint: this.inviter_endpoint,
      inviter_discovery_url: this.inviter_discovery_url,
      proposed_deal_type: this.proposed_deal_type,
      proposed_session_params: this.proposed_session_params,
      proposed_terms_summary: this.proposed_terms_summary,
      inviter_mandate_summary: this.inviter_mandate_summary,
      invitation_expires_at: this.invitation_expires_at,
      accept_endpoint: this.accept_endpoint,
      decline_endpoint: this.decline_endpoint,
      inviter_verification_method: this.inviter_verification_method,
      invitation_signature: this.invitation_signature || null,
    });
  }
}

export class InvitationAcceptance {
  message_type: string; // "invitation_acceptance"
  invitation_id: string;
  acceptor_did: string;
  acceptor_a2cn_endpoint: string;
  acceptor_discovery_url: string;
  accepted_at: string; // ISO 8601 UTC
  acceptor_verification_method: string;
  acceptance_signature: string;

  constructor(props: {
    message_type: string;
    invitation_id: string;
    acceptor_did: string;
    acceptor_a2cn_endpoint: string;
    acceptor_discovery_url: string;
    accepted_at: string;
    acceptor_verification_method: string;
    acceptance_signature?: string;
  }) {
    this.message_type = props.message_type;
    this.invitation_id = props.invitation_id;
    this.acceptor_did = props.acceptor_did;
    this.acceptor_a2cn_endpoint = props.acceptor_a2cn_endpoint;
    this.acceptor_discovery_url = props.acceptor_discovery_url;
    this.accepted_at = props.accepted_at;
    this.acceptor_verification_method = props.acceptor_verification_method;
    this.acceptance_signature = props.acceptance_signature ?? "";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      invitation_id: this.invitation_id,
      acceptor_did: this.acceptor_did,
      acceptor_a2cn_endpoint: this.acceptor_a2cn_endpoint,
      acceptor_discovery_url: this.acceptor_discovery_url,
      accepted_at: this.accepted_at,
      acceptor_verification_method: this.acceptor_verification_method,
      acceptance_signature: this.acceptance_signature || null,
    });
  }
}

export class InvitationDecline {
  message_type: string; // "invitation_decline"
  invitation_id: string;
  reason_code: string; // DEAL_TYPE_NOT_SUPPORTED | MANDATE_INSUFFICIENT | CAPACITY | OTHER
  declined_at: string;
  reason_message: string;

  constructor(props: {
    message_type: string;
    invitation_id: string;
    reason_code: string;
    declined_at: string;
    reason_message?: string;
  }) {
    this.message_type = props.message_type;
    this.invitation_id = props.invitation_id;
    this.reason_code = props.reason_code;
    this.declined_at = props.declined_at;
    this.reason_message = props.reason_message ?? "";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      invitation_id: this.invitation_id,
      reason_code: this.reason_code,
      declined_at: this.declined_at,
      reason_message: this.reason_message || null,
    });
  }
}

// ---------------------------------------------------------------------------
// v0.2.0: Webhook Payload (Level 2 conformance — REQUIRED)
// ---------------------------------------------------------------------------

export class WebhookPayload {
  event_type: string; // "session.completed" | "session.rejected" | "session.withdrawn"
  // | "session.impasse" | "session.timed_out" | "session.error"
  session_id: string;
  occurred_at: string; // ISO 8601 UTC
  session_state: string;
  terminal: boolean; // always true for these events
  a2cn_version: string;
  record_hash: string; // populated only for session.completed

  constructor(props: {
    event_type: string;
    session_id: string;
    occurred_at: string;
    session_state: string;
    terminal: boolean;
    a2cn_version?: string;
    record_hash?: string;
  }) {
    this.event_type = props.event_type;
    this.session_id = props.session_id;
    this.occurred_at = props.occurred_at;
    this.session_state = props.session_state;
    this.terminal = props.terminal;
    this.a2cn_version = props.a2cn_version ?? "0.2";
    this.record_hash = props.record_hash ?? "";
  }

  toDict(): Dict {
    return dropNone({
      event_type: this.event_type,
      session_id: this.session_id,
      occurred_at: this.occurred_at,
      session_state: this.session_state,
      terminal: this.terminal,
      a2cn_version: this.a2cn_version,
      record_hash: this.record_hash || null,
    });
  }
}

// ---------------------------------------------------------------------------
// v0.2.0: Invitation error codes (Section 11.7 extension)
// ---------------------------------------------------------------------------

export const INVITATION_EXPIRED = "INVITATION_EXPIRED";
export const INVITATION_NOT_FOUND = "INVITATION_NOT_FOUND";
export const INVITATION_SIGNATURE_INVALID = "INVITATION_SIGNATURE_INVALID";
export const INVITATION_ALREADY_ANSWERED = "INVITATION_ALREADY_ANSWERED";
export const INVITATION_VERSION_MISMATCH = "INVITATION_VERSION_MISMATCH";

// ---------------------------------------------------------------------------
// v0.2.0: Post-commitment lifecycle (OQ-017 resolved; Level 3 conformance)
// ---------------------------------------------------------------------------

function nowIsoSeconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Sent by the seller to confirm delivery against a completed session.
 * References the transaction record by hash. Required for Level 3
 * conformance in A2CN v0.2.0.
 *
 * A `delivery_notice` closes the seller's obligation under the agreed terms
 * and triggers the buyer's acknowledgment window.
 */
export class DeliveryNoticeMessage {
  message_id: string;
  session_id: string;
  transaction_record_hash: string; // Must match the agreed transaction record
  delivery_timestamp: string; // ISO 8601 — when delivery occurred
  delivery_reference: string | null; // Tracking number, PO ref, etc.
  notes: string | null;
  protocol_version: string;
  message_type: string;

  constructor(props: {
    message_id: string;
    session_id: string;
    transaction_record_hash: string;
    delivery_timestamp: string;
    delivery_reference?: string | null;
    notes?: string | null;
    protocol_version?: string;
    message_type?: string;
  }) {
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.transaction_record_hash = props.transaction_record_hash;
    this.delivery_timestamp = props.delivery_timestamp;
    this.delivery_reference = props.delivery_reference ?? null;
    this.notes = props.notes ?? null;
    this.protocol_version = props.protocol_version ?? "0.2";
    this.message_type = props.message_type ?? "delivery_notice";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      transaction_record_hash: this.transaction_record_hash,
      delivery_timestamp: this.delivery_timestamp,
      delivery_reference: this.delivery_reference,
      notes: this.notes,
      protocol_version: this.protocol_version,
    });
  }
}

/**
 * Sent by the buyer to acknowledge receipt of a `delivery_notice`.
 * Closes the post-commitment lifecycle when accepted=true.
 * When accepted=false, triggers DISPUTED status on the session.
 *
 * References both the `delivery_notice` and the transaction record.
 */
export class DeliveryAcknowledgedMessage {
  message_id: string;
  session_id: string;
  transaction_record_hash: string; // Must match agreed transaction record
  delivery_notice_message_id: string; // References the delivery_notice
  acknowledgment_timestamp: string; // ISO 8601
  accepted: boolean; // true = delivery accepted, false = disputed
  notes: string | null;
  protocol_version: string;
  message_type: string;

  constructor(props: {
    message_id: string;
    session_id: string;
    transaction_record_hash: string;
    delivery_notice_message_id: string;
    acknowledgment_timestamp: string;
    accepted: boolean;
    notes?: string | null;
    protocol_version?: string;
    message_type?: string;
  }) {
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.transaction_record_hash = props.transaction_record_hash;
    this.delivery_notice_message_id = props.delivery_notice_message_id;
    this.acknowledgment_timestamp = props.acknowledgment_timestamp;
    this.accepted = props.accepted;
    this.notes = props.notes ?? null;
    this.protocol_version = props.protocol_version ?? "0.2";
    this.message_type = props.message_type ?? "delivery_acknowledged";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      transaction_record_hash: this.transaction_record_hash,
      delivery_notice_message_id: this.delivery_notice_message_id,
      acknowledgment_timestamp: this.acknowledgment_timestamp,
      accepted: this.accepted,
      notes: this.notes,
      protocol_version: this.protocol_version,
    });
  }
}

/**
 * Sent by either party to formally open a dispute referencing a
 * committed or delivered session. Freezes further automated processing
 * and anchors the dispute to the agreed transaction record.
 *
 * Disputes should be routed to a neutral resolver. A neutral third-party
 * custodian may provide evidence custody and dispute resolution as an
 * optional hosted service.
 */
export class DisputeNoticeMessage {
  message_id: string;
  session_id: string;
  transaction_record_hash: string; // Must match agreed transaction record
  raised_by: string; // "buyer" or "seller"
  dispute_type: string; // "non_delivery" | "wrong_quantity" | "quality"
  // | "payment_failure" | "terms_violation" | "other"
  description: string;
  evidence_references: string[]; // Document refs, hashes, URLs
  resolution_requested: string | null; // "renegotiate" | "cancel" | "neutral_review"
  dispute_timestamp: string; // ISO 8601, auto-set on creation
  protocol_version: string;
  message_type: string;

  constructor(props: {
    message_id: string;
    session_id: string;
    transaction_record_hash: string;
    raised_by: string;
    dispute_type: string;
    description: string;
    evidence_references?: string[] | null;
    resolution_requested?: string | null;
    dispute_timestamp?: string | null;
    protocol_version?: string;
    message_type?: string;
  }) {
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.transaction_record_hash = props.transaction_record_hash;
    this.raised_by = props.raised_by;
    this.dispute_type = props.dispute_type;
    this.description = props.description;
    this.evidence_references = props.evidence_references ?? [];
    this.resolution_requested = props.resolution_requested ?? null;
    this.dispute_timestamp = props.dispute_timestamp ?? nowIsoSeconds();
    this.protocol_version = props.protocol_version ?? "0.2";
    this.message_type = props.message_type ?? "dispute_notice";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      transaction_record_hash: this.transaction_record_hash,
      raised_by: this.raised_by,
      dispute_type: this.dispute_type,
      description: this.description,
      evidence_references: this.evidence_references,
      resolution_requested: this.resolution_requested,
      dispute_timestamp: this.dispute_timestamp,
      protocol_version: this.protocol_version,
    });
  }
}

/**
 * Sent by the neutral resolver (or agreed party) to record the outcome
 * of a dispute opened by `dispute_notice`. Closes the post-commitment
 * dispute lifecycle.
 *
 * Anchored to both the original transaction record hash and the
 * `dispute_notice` message_id. The resolution_outcome field records
 * who prevailed; resolver_did identifies the neutral party that
 * issued the resolution.
 *
 * Concordia Protocol composition note: this message provides the
 * stable input shape for Concordia fulfillment attestations with
 * fulfillment.status = "fulfilled_with_mediation" and
 * meta.mediator_invoked = true. Both the transaction_record_hash
 * and dispute_notice_message_id are required fields for that
 * composition seam.
 */
export class DisputeResolvedMessage {
  message_id: string;
  session_id: string;
  transaction_record_hash: string; // Must match the agreed transaction record
  dispute_notice_message_id: string; // References the dispute_notice being resolved
  resolution_outcome: string; // "buyer_prevails" | "seller_prevails" | "mutual_settlement"
  resolver_did: string; // DID of the neutral resolver
  resolution_timestamp: string; // ISO 8601, auto-set on creation
  resolution_notes: string | null;
  evidence_references: string[]; // Supporting evidence for the ruling
  protocol_version: string;
  message_type: string;

  constructor(props: {
    message_id: string;
    session_id: string;
    transaction_record_hash: string;
    dispute_notice_message_id: string;
    resolution_outcome: string;
    resolver_did: string;
    resolution_timestamp?: string | null;
    resolution_notes?: string | null;
    evidence_references?: string[] | null;
    protocol_version?: string;
    message_type?: string;
  }) {
    this.message_id = props.message_id;
    this.session_id = props.session_id;
    this.transaction_record_hash = props.transaction_record_hash;
    this.dispute_notice_message_id = props.dispute_notice_message_id;
    this.resolution_outcome = props.resolution_outcome;
    this.resolver_did = props.resolver_did;
    this.resolution_timestamp = props.resolution_timestamp ?? nowIsoSeconds();
    this.resolution_notes = props.resolution_notes ?? null;
    this.evidence_references = props.evidence_references ?? [];
    this.protocol_version = props.protocol_version ?? "0.2";
    this.message_type = props.message_type ?? "dispute_resolved";
  }

  toDict(): Dict {
    return dropNone({
      message_type: this.message_type,
      message_id: this.message_id,
      session_id: this.session_id,
      transaction_record_hash: this.transaction_record_hash,
      dispute_notice_message_id: this.dispute_notice_message_id,
      resolution_outcome: this.resolution_outcome,
      resolver_did: this.resolver_did,
      resolution_timestamp: this.resolution_timestamp,
      resolution_notes: this.resolution_notes,
      evidence_references: this.evidence_references,
      protocol_version: this.protocol_version,
    });
  }
}

/**
 * Concordia-shaped artifact emitted when A2CN post-commitment fulfillment
 * reaches a clean or mediated terminal state.
 */
export class FulfillmentAttestation {
  attestation_type: string;
  id: string;
  issued_at: string;
  agreement_attestation_id: string;
  fulfillment: Dict;
  references: Dict[];
  signature: Dict;
  meta: Dict | null;

  constructor(props: {
    attestation_type: string;
    id: string;
    issued_at: string;
    agreement_attestation_id: string;
    fulfillment: Dict;
    references: Dict[];
    signature: Dict;
    meta?: Dict | null;
  }) {
    this.attestation_type = props.attestation_type;
    this.id = props.id;
    this.issued_at = props.issued_at;
    this.agreement_attestation_id = props.agreement_attestation_id;
    this.fulfillment = props.fulfillment;
    this.references = props.references;
    this.signature = props.signature;
    this.meta = props.meta ?? null;
  }

  toDict(): Dict {
    return dropNone({
      attestation_type: this.attestation_type,
      id: this.id,
      issued_at: this.issued_at,
      agreement_attestation_id: this.agreement_attestation_id,
      fulfillment: this.fulfillment,
      references: this.references,
      signature: this.signature,
      meta: this.meta,
    });
  }
}

/**
 * Validates terms dict against deal-type-specific schema.
 * Returns list of validation error strings. Empty list = valid.
 *
 * goods_procurement required fields: delivery_days (int >= 1)
 * saas_renewal required fields: seat_count (int >= 1)
 * Unknown deal types: always valid (extensible).
 */
export function validateDealTypeTerms(dealType: string, terms: Dict): string[] {
  const errors: string[] = [];

  const isInt = (v: unknown): v is number =>
    typeof v === "number" && Number.isInteger(v) && typeof v !== "boolean";

  if (dealType === "goods_procurement") {
    const deliveryDays = terms.delivery_days;
    if (deliveryDays === null || deliveryDays === undefined) {
      errors.push("goods_procurement terms require 'delivery_days'");
    } else if (typeof deliveryDays === "boolean" || !isInt(deliveryDays)) {
      errors.push(`delivery_days must be an integer >= 1, got ${JSON.stringify(deliveryDays)}`);
    } else if (deliveryDays < 1) {
      errors.push(`delivery_days must be >= 1, got ${deliveryDays}`);
    }
  } else if (dealType === "saas_renewal") {
    const seatCount = terms.seat_count;
    if (seatCount === null || seatCount === undefined) {
      errors.push("saas_renewal terms require 'seat_count'");
    } else if (typeof seatCount === "boolean" || !isInt(seatCount)) {
      errors.push(`seat_count must be an integer >= 1, got ${JSON.stringify(seatCount)}`);
    } else if (seatCount < 1) {
      errors.push(`seat_count must be >= 1, got ${seatCount}`);
    }
  }

  // Unknown deal types pass through without validation (extensibility)
  return errors;
}
