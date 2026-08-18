# ADR-0002 — Cloudflare Terms of Service and Tier A

**Status:** ESCALATED — requires a human decision. Do not proceed past P1
planning on Tier A until this is answered.
**Closes:** 04-STATUS.md 2.4 (research complete; decision outstanding)
**Author's standing:** engineer, not a lawyer. Everything below is research to
inform counsel and the project lead, not legal advice.

---

## The question

01-ARCHITECTURE.md makes Tier A — user traffic tunnelled as VLESS-over-
WebSocket through a Cloudflare-proxied domain — the load-bearing
whitelist-resistant tier. 04-STATUS.md 2.4 flagged that this likely violates
Cloudflare's terms and recorded it as unresearched. It is now researched.

## What the research found

**Cloudflare updated its Terms of Service on 3 December 2024 to state
explicitly that proxy services, such as a VPN service, may not run on
Cloudflare's network unless expressly approved.** Before that date the
prohibition was inferred from the old Section 2.8 (a restriction on serving
non-HTML content), which Cloudflare removed in 2023 and replaced with
CDN-specific service terms. The current position is not an inference. It names
the thing.

Two things follow, and they are different from each other.

**Tier A as designed is the prohibited activity.** Routing user traffic through
Workers and the CDN is a proxy service on Cloudflare's network. There is no
reading of the current terms under which it is permitted by default.

**The distributor and collector Workers are not.** They are ordinary JSON
APIs — credential issuance and measurement collection. No user traffic passes
through them. They serve small text responses to authenticated clients. That is
an unremarkable Workers workload and nothing in the terms speaks against it.

The relevant enforcement risk is therefore concentrated in one component, not
spread across the whole Cloudflare footprint.

### The failure mode that matters most

01-ARCHITECTURE.md's stated reason for putting the distributor on Workers is
that **the distribution channel must live in a different failure domain than
the transport it describes.** If the subscription URL dies with the proxies,
you are hand-delivering configs to millions of people.

Running Tier A on the same Cloudflare account re-couples exactly those failure
domains through a channel the architecture did not consider: **a terms-of-service
enforcement action against the account takes down the distribution plane and
the transport at the same moment.** That is strictly worse than the outcome the
architecture was designed to avoid, and it happens on Cloudflare's schedule,
without notice, at the point of maximum usage — because usage is what triggers
review.

### Sanctions are not the obstacle

Worth recording because it is the question people ask next, and the answer is
favourable. US sanctions law explicitly authorises this category of work:
OFAC General License D-2 (issued 23 September 2022, superseding D-1, and
incorporated into 31 CFR § 560.540 by amendment on 17 May 2024) authorises
export to Iran of anti-censorship tools, VPN client software, and related
services. The blocker here is **contractual, not statutory.** Confirm with
counsel; do not act on this paragraph alone.

## Options

**A. Separate Cloudflare accounts — do this regardless of what else is decided.**
Distribution and measurement on an account that never carries tunnelled
traffic. Tier A, if it runs on Cloudflare at all, on a different account with a
different billing identity. Cheap, immediate, and it restores the failure-domain
separation the architecture assumes. This is a prerequisite, not an option.

**B. Seek express approval.** The terms say "unless expressly approved," so an
approval path exists. Cloudflare has a public-interest posture (Project
Galileo) and has supported at-risk civil-society infrastructure before. This is
a conversation with Cloudflare's public-interest and enterprise teams, initiated
honestly, describing exactly what the traffic is and who it is for. Slow,
possibly unsuccessful, and the only option that makes Tier A durable on
Cloudflare rather than merely undetected.

**C. Move Tier A to a provider whose terms permit it.** Any CDN or fronting
provider that allows tunnelled traffic contractually. Preserves the tier's
purpose. Requires finding one whose whitelist-resistance is comparable, and
that property comes precisely from being too big and too commercially embedded
to block — the same size that comes with the strictest terms.

**D. Narrow Tier A to the control channel only.** Keep Cloudflare for
credential issuance, subscription polling, and measurement collection — the
things it is unambiguously allowed to do and the things that must survive a
default-deny event. Move bulk user traffic to Tier D and the P4 second-shape
fleet. This gives up whitelist-resistant *bandwidth* and keeps
whitelist-resistant *bootstrap*, which is the half that determines whether a
user can recover at all.

**E. Do it anyway and hope.** Named so it can be rejected explicitly. The
enforcement outcome is account termination, at scale, without notice, with the
distribution plane inside the blast radius. Users under a hostile government
lose access at the moment the system is most used. Reject.

## Recommendation

**A + D now, B in parallel, C as the contingency.**

Separate the accounts this week — it is nearly free and it removes the worst
failure mode whatever else is decided. Scope Tier A down to the control channel
so the design stops depending on a prohibited activity, and let Tier D plus the
P4 second-shape fleet carry bulk traffic. Open the conversation with Cloudflare
honestly; if approval comes, Tier A can be widened back with a contract behind
it rather than an assumption.

The reasoning behind ranking D over C: a tier that is contractually prohibited
is not a tier, it is a countdown. Building the client (P2) against a transport
that may be terminated without notice means shipping users a failover path that
has never been exercised at the moment it is needed most.

## What this changes if accepted

- 01-ARCHITECTURE.md's Tier A section needs revising, and that is an
  architecture change requiring its own ADR and the human's sign-off.
- 02-RUNBOOK.md §1 Stage 2 must instruct operators to use a separate account.
- P4 (second-shape transport) moves up the priority order, because it stops
  being diversity and starts being the bulk path.

## Open questions for the human

1. Is anyone willing to have the conversation with Cloudflare under a real
   identity? Option B requires it, and it is not a decision an engineer makes
   for someone else — it attaches a name to the project.
2. Does the project have counsel who can read the current terms and confirm the
   reading above?
3. Is there an existing relationship with any CDN or hosting provider that
   would make option C concrete rather than hypothetical?

## Sources

- [Cloudflare — Goodbye, section 2.8 and hello to Cloudflare's new terms of service](https://blog.cloudflare.com/updated-tos)
- [LowEndTalk — CloudFlare Updates Terms of Service, Is the Era of the Workers-VPN Coming to an End?](https://lowendtalk.com/discussion/200904/cloudflare-updates-terms-of-service-is-the-era-of-the-workers-vpn-coming-to-an-end)
- [Cloudflare — Service-Specific Terms](https://www.cloudflare.com/service-specific-terms-zero-trust-services/)
- [US Treasury — Iran General License D-2 to Increase Support for Internet Freedom](https://content.govdelivery.com/accounts/USTREAS/bulletins/32e8e10)
- [Baker McKenzie — OFAC Issues Updated Iran General License](https://sanctionsnews.bakermckenzie.com/ofac-issues-updated-iran-general-license-related-to-certain-services-software-and-hardware-for-communications-over-the-internet-and-new-related-faqs/)
- [OFAC FAQs (updated 2024-05-16)](https://ofac.treasury.gov/faqs/updated/2024-05-16)

**Primary sources were not read directly:** `www.cloudflare.com` is blocked by
this environment's network egress proxy, so the terms language above comes from
secondary reporting and must be confirmed against the live terms before any
decision is taken on it.
