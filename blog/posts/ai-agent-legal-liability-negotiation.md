---
title: "Who Owns the Legal Liability When Your AI Agent Negotiates a Deal?"
description: "There's no clean answer yet — but the direction of travel is visible. Contract law already permits machine-made deals; agency doctrine points at the deployer; and courts, regulators, and payment networks are converging on the same conclusion: authority disputes will be decided on evidence."
date: 2026-07-03
slug: ai-agent-legal-liability-negotiation
---

# Who Owns the Legal Liability When Your AI Agent Negotiates a Deal?

*This is a state-of-play piece, not legal advice. If you're deploying agents that make commercial commitments, talk to an actual lawyer.*

Ask an enterprise legal team why their procurement agent still routes every commitment through a human approver, and you'll usually hear some version of "the law isn't settled." That's true, but it's imprecise in a way that matters. The interesting thing about mid-2026 is *which parts* are unsettled. The validity of machine-made contracts isn't the open question — that was answered decades ago. What's unsettled is narrower and more practical: when an agent commits its company to something, how does anyone prove what it was authorized to do?

That reframing — from a doctrine problem to an evidence problem — is the single most useful lens for understanding where this is heading. Courts, regulators, standards bodies, and payment networks are all converging on it from different directions.

## The part that's already settled: machines can make contracts

In the United States, the legal substrate for autonomous commercial commitment has existed since before most of today's AI companies were founded. The federal E-SIGN Act says a contract can't be denied legal effect solely because an "electronic agent" was involved in forming it — with one crucial condition: the agent's action must be *legally attributable to the person to be bound*. UETA, adopted in 49 states, goes further: a contract may be formed by the interaction of electronic agents "even if no individual was aware of or reviewed the electronic agents' actions or the resulting terms and agreements." The drafters wrote that in 1999, and they even anticipated systems that "learn through experience" and "modify the instructions in their own programs."

Internationally, the trajectory is the same. UNCITRAL's 2024 Model Law on Automated Contracting explicitly provides legal recognition for AI in contract formation and performance, and addresses attribution of automated outputs — including unexpected ones.

Notice what both frameworks do, though. They don't say the machine is a party. They say the machine's acts get attributed to *someone* — and then they hand all the hard questions back to ordinary doctrine. Attribution is the whole game.

## The most useful lens is 150 years old

Principal–agent doctrine remains the best framework anyone has for AI agents, and it maps more cleanly than you'd expect. An agreement made by an agent binds the principal when it falls within the agent's actual authority, or within the authority a third party reasonably perceived. Actual authority can be express or implied. Apparent authority arises when the principal's own conduct leads a counterparty to reasonably believe the actor was authorized. And if an agent exceeds its instructions but the company keeps the benefits of the deal, ratification kicks in.

Map that onto an AI procurement agent and the questions write themselves. Configure an agent with bounded commercial authority, authenticate it to your suppliers, and let it transact within those bounds — that's the actual-authority pattern. Put your agent in an authenticated channel where counterparties reasonably assume it speaks for you — apparent authority gets stronger, whether or not you intended it. Let a deal stand after your agent overstepped — you've likely ratified it.

The doctrine never asks whether the model "intended" anything. It asks what the company set up, what the counterparty reasonably believed, and what happened afterward. Which means the decisive material in a future dispute won't be philosophical — it will be configuration files, credential scopes, policy thresholds, and logs.

Courts are already behaving this way in adjacent territory. When Air Canada argued that its website chatbot was "a separate legal entity responsible for its own actions," the tribunal called the submission remarkable and held the airline liable anyway. Wrong-doctrine cases like that one keep producing the same instinct: the deployer answers for the agent.

## The case law is thin — and the closest case is about a different question

Here's the honest state of the docket: as of July 2026, there is still no reported U.S. or EU decision squarely resolving liability for an enterprise AI agent that independently negotiated and bound its company to a supplier contract. Baker McKenzie's June 2026 survey of the landscape says plainly that few U.S. laws or judicial decisions explicitly address AI agents yet. The law here is being assembled from adjacent fights.

The most watched of those fights is *Amazon v. Perplexity*. In March 2026, Judge Maxine Chesney of the Northern District of California granted Amazon a preliminary injunction, finding strong evidence that Perplexity's Comet agent accessed Amazon's password-protected systems "with the Amazon user's permission, but without authorization by Amazon" — a violation of the Computer Fraud and Abuse Act. The Ninth Circuit stayed the injunction, heard oral argument in Seattle on June 11, and has the case under submission as this is written. Amici lined up on both sides: EFF, Mozilla, and the ACLU behind Perplexity; developer, finance, and airline industry groups behind Amazon.

It's not a contract-formation case. But it crystallizes a distinction every agentic commerce architecture now has to reckon with: *the principal's instruction to the agent is not the same thing as the counterparty's authorization of the agent.* Your customer telling your agent to act does not mean the system on the other side has agreed to deal with it. Whatever the Ninth Circuit decides, that two-sided authorization question is now live law — and it's precisely the question that gets harder, not easier, when both sides of a transaction field agents.

## Regulators are saying the quiet part out loud

The EU AI Act matters here, but not the way people assume. It governs through risk categories and oversight obligations — logging, monitoring, human oversight by design for high-risk systems — not through any rule about whether an AI-made commitment binds. It's governance architecture, not contract law. Nobody should read it as either permitting or prohibiting autonomous dealmaking as such.

The more interesting signals are coming from financial supervisors. On June 30, 2026, Bank of England Deputy Governor Sarah Breeden said existing frameworks weren't built for autonomous agents — and, notably, that relying on a human in the loop for every agent action would be *unrealistic*, especially in payments and trading. That's a central banker saying the human-approval gate doesn't scale. The Financial Stability Board opened its own consultation on AI in finance the same month. The supervisory world has stopped treating agent autonomy as speculative and started treating it as an accountability-engineering problem.

And in the U.S., the clearest marker of where this is going came from NIST. In February 2026, its National Cybersecurity Center of Excellence published a concept paper — comments closed April 2 — on software and AI agent identity and authorization, framed explicitly around four things: identification, authorization, auditing, and *non-repudiation*. Read that list again. It's not a list of AI-safety concepts. It's a list of evidence concepts. The U.S. standards apparatus has effectively concluded that the agent-authority problem is an identity-and-proof problem.

One public comment on that NIST docket argued that identity and access controls, while necessary, aren't sufficient for autonomous agents — and proposed complementing them with "explicit mandate specification, policy-envelope binding, and delegation-chain modeling." We didn't write that comment. But we could have. That's the entire thesis of the protocol layer we work on, showing up independently in a federal standards conversation.

## The payment networks already built for the dispute

If you want to know how sophisticated institutions think liability will actually be resolved, don't read their legal commentary — read their infrastructure.

Visa's Trusted Agent Protocol exists so merchants can verify that an agent is a known, commerce-intent actor rather than hostile automation. Mastercard's Verifiable Intent, announced in March 2026, is the most explicit of all: a tamper-resistant record linking identity, user instruction, and resulting transaction, providing — in Mastercard's own words — "facts, not guesswork" when something goes wrong. It cryptographically proves authorization, captures whether a human was present, and produces an audit trail for disputes. Google's AP2 protocol reaches the same design from the protocol side, using cryptographically signed *mandates* to establish authorization and accountability, with distinct patterns for human-present and delegated transactions — and its own documentation extends the model to B2B procurement.

None of this is contract law. All of it is the same bet: that when an agent-made commitment gets disputed, the fight will be won or lost on provable identity, provable scope of delegation, and a record neither side can unilaterally rewrite. The card networks aren't waiting for courts to say so. They're building the evidence layer now, because they're the ones who eat the fraud losses when authority is ambiguous.

## So who owns the liability?

Pulling the threads together, the mid-2026 answer looks like this:

The *company that deployed the agent* is the center of gravity — through attribution under electronic-contracting law, through actual and apparent authority under agency doctrine, and through ratification when it keeps the benefits. "The AI did it" has no more legal force than "my employee did it." Courts extending old doctrine into new facts have shown no appetite for treating the software as an intervening actor.

What remains genuinely open is the boundary question: where authorized autonomy ends and unauthorized overreach begins in a real B2B dispute — and, after *Amazon v. Perplexity*, whose authorization even counts when an agent crosses into someone else's system. When those cases arrive, the decisive facts will be mundane: which agent acted, under whose authority, within what encoded limits, visible to whom, and with what record.

Which is why every serious actor in this space — NIST, the card networks, the FIDO Alliance's new agentic working group, enterprise legal teams writing AI addenda — has converged on the same practical demand: **make authority verifiable before the dispute, not arguable after it.**

That's an infrastructure requirement wearing a legal question's clothes. A negotiation between two enterprise agents needs the authority of each agent declared and cryptographically verifiable to the counterparty, and it needs both sides to walk away holding an identical, tamper-evident record of what was agreed and under what mandate. Build that, and most of the liability fog resolves into checkable facts. Skip it, and every disputed deal becomes an archaeology project through two companies' incompatible logs.

The law will take years to finish answering the liability question. The evidence problem can be solved now. That's the layer we're building at A2CN — and if the past six months of court filings, supervisor speeches, and standards dockets are any guide, it's the layer the rest of the answer will eventually stand on.
