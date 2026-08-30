# ADR-0007 — Where Tier A goes after Cloudflare

**Status:** RESEARCH, incomplete. Not a decision.
**Follows:** ADR-0002, which decided Tier A does not stay on Cloudflare and
left the provider question open.
**Blocking:** P4, which is now the bulk path rather than the diversity layer.

---

## What this memo is

ADR-0002 chose to move CDN-fronted transport off Cloudflare rather than seek
permission to keep it there. That created an open question — *where to* — and
this records what could and could not be established about it.

**It does not name a provider.** It could not, honestly: the primary sources are
unreadable from this environment (`cloudflare.com`, `bunny.net` and others are
blocked by the sandbox's egress proxy, and search snippets do not carry clause
text). Every claim below is secondary reporting and **must be checked against
the live terms before anyone acts on it.** A ToS answer sourced from a summary
is exactly the mistake ADR-0002 was written to correct.

## What the research did establish

**The technique still works.** As of 2026, CDN fronting remains effective for
Iran: Lantern reports its CDN-fronted "proxyless" protocol carrying roughly 40%
of its Iranian traffic, and Fastly, Google and Vercel are reported to still
front. That is evidence about *reachability*, and it is the harder half of the
question — a provider whose terms permit tunnelling but whose edge is blocked in
Tehran is worth nothing.

**A distinction worth carrying into P4.** Tool designers must separate "blocked
by the censor" from "the provider refuses Iranian IPs". Only the first is
addressable by fronting; the second is a sanctions-compliance posture on the
provider's side and fronting does not fix it. The two look identical from
outside the country, which is the same trap 01-ARCHITECTURE warns about for
node health.

**Fronting is revocable everywhere.** Every provider that fronts today does so
as an accident of configuration, not a commitment. It has been withdrawn before,
at short notice, under political pressure. Whatever is chosen, the client's
failover to Tier D and the P4 second-shape fleet must be exercised and not
assumed — which is P2 and P4 work, not procurement.

## What is NOT established

- Whether Fastly's, Bunny's, Gcore's or any other provider's terms permit
  relaying third-party traffic. **Unknown.** Not "probably fine" — unknown.
- Whether any of them will hold that position for a project that says plainly
  what it is. Asking is itself a decision with consequences, as ADR-0002 notes.
- Whether an operator can hold an account at each without exposing an identity
  that connects to the project.

## The questions each candidate has to answer

Written as a checklist so this can be handed to someone with a browser and a
lawyer, which is what it needs.

1. **Terms.** Does the acceptable-use policy prohibit proxying, tunnelling,
   VPN services, or relaying third-party traffic? Quote the clause. If silent,
   that is not permission — get it in writing.
2. **Reachability from Iran.** Is the edge reachable today, measured from
   inside, not from a European vantage point? This is the only measurement that
   counts (01-ARCHITECTURE's central rule).
3. **Iranian-IP posture.** Does the provider itself refuse Iranian clients for
   sanctions reasons? Fronting cannot fix this.
4. **Jurisdiction and pressure surface.** Where incorporated, and who can compel
   them. Note that OFAC GL D-2 / 31 CFR § 560.540 makes this work lawful for US
   providers; the obstacle everywhere so far has been contractual, not statutory.
5. **Account identity.** Can it be held without linking to a person the project
   cannot afford to expose? Payment, verification, and support channels all
   count.
6. **Failure domain.** It must not be the same account, company, or ASN family
   as the distribution plane. Re-coupling those is the mistake ADR-0002 exists
   to prevent, and moving to a new provider is exactly when it gets made again.
7. **Termination behaviour.** Notice period, appeal path, and whether the
   account dies with the service. Assume ejection; plan for it.

## Recommendation for sequencing

Do not block P2 on this. The client is the critical path, it must fail over
between tiers regardless of which providers exist, and a client built against
Tier D plus a second-shape transport works whatever answer arrives here.

Do block P4's provider selection on it, and give item 2 — measured reachability
from inside Iran — priority over items 1 and 3. A permitted, lawful, reachable
provider is the goal; permitted and lawful but unreachable is a waste of the
procurement effort.

## Sources

- [Lantern circumvention corpus — MITM-DomainFronting / Xray-core integration, 2026](https://corpus.lantern.io/findings/2026-patterniha-mitm-domainfronting__xray-core-integration-ip-blocking-iran/)
- [net4people/bbs — TLSOS: Censorship Circumvention via CDNs](https://github.com/net4people/bbs/issues/571)
- [Lantern circumvention corpus — findings index](https://corpus.lantern.io/findings/)
- [Fastly acceptable use policy](https://www.fastly.com/acceptable-use) — *not read; page unreachable from the build environment*
- [Wikipedia — Domain fronting](https://en.wikipedia.org/wiki/Domain_fronting)
