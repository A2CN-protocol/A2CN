# A2CN — Agent-to-Agent Commercial Negotiation Protocol

**An open protocol for machine-to-machine B2B commerce.**

---

## The problem

Every existing protocol for AI agent interaction was built for a specific layer:

- **MCP** — agent to tool
- **A2A** — agent communication
- **UCP / ACP** — consumer retail checkout
- **AP2** — payment execution

None of them define what happens when two agents from *different organizations*, 
representing *competing interests*, need to exchange offers, verify each other's 
authority to commit, and produce a jointly-trusted record of what was agreed.

That layer does not exist.

## The concrete failure

A procurement agent at Company A initiates a negotiation with a supplier whose 
agent runs on a different platform. Today, this falls back to email and a 
human-facing chat interface. As both sides of B2B transactions deploy agents, 
this failure mode becomes the norm.

What is the protocol that lets those two agents negotiate directly — machine to 
machine — with neither party controlling the authoritative transaction record?

## What A2CN defines

A minimal open protocol covering six components:

1. **Discovery** — `/.well-known/a2cn-agent` endpoint for agent capability advertisement
2. **Mandate verification** — cryptographic proof that an agent has authority to commit 
   (W3C DIDs)
3. **Offer exchange schema** — canonical message format for offers, counteroffers, 
   acceptances, and rejections
4. **Session state machine** — defined negotiation phases, round limits, timeout 
   handling, and impasse detection
5. **Transaction record** — immutable, content-addressed, signed by both parties
6. **Compliance trace** — structured audit output for EU AI Act requirements

## What A2CN is not

- A negotiation strategy or pricing engine
- A platform or SaaS product
- A competitor to MCP, A2A, UCP, ACP, or AP2 — it is complementary to all of them
- Controlled by any single commercial entity

## Status

**v0.1 specification: in active development.**

The specification lives in `/spec`. The reference implementation is in 
`/reference-implementation`. The SDK is in `/sdk`.

## Contributing

We are looking for:

- Engineers with protocol and distributed systems experience
- Developers building procurement or sales agents who have encountered 
  this problem directly
- Feedback on the specification design

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

Open issues are tagged [`help wanted`] and [`good first issue`].
