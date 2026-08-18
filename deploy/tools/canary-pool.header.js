/**
 * canary-pool.js — GENERATED, do not edit by hand.
 *   regenerate: node tools/build-canary-pool.mjs
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * WHAT A CANARY IS FOR
 *
 * Every work manifest carries decoy targets that are not our nodes. A canary
 * is issued to exactly ONE slot, so if that canary is ever reported blocked
 * while other slots reach the same host fine, the reporting slot is lying —
 * which is the signature of a censor feeding false blocks to burn healthy
 * nodes. Attribution becomes exact instead of statistical.
 *
 * WHAT WAS WRONG BEFORE (04-STATUS.md defect 2.5)
 *
 * The pool was three hardcoded domains. A censor who enrolled twice saw the
 * same three hosts in both manifests and identified the entire mechanism in
 * one afternoon — after which every canary is answered truthfully and every
 * real node is answered falsely, and the detector is worse than useless
 * because it now certifies the attacker as trustworthy.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  TWO POOLS, AND AN HONEST STATEMENT OF WHAT EACH ACHIEVES
 * ───────────────────────────────────────────────────────────────────────────
 *
 * OPERATOR POOL (KV `canary_pool`, set via /admin/canary-pool) — the real
 * answer. Decoy hosts the operator runs on the SAME providers and ASNs as the
 * real fleet, serving an ordinary website and no proxy. These are not
 * separable from real nodes by address, ASN, or TLS shape, because in every
 * respect except purpose they are the same kind of machine. Populate this
 * before enrolling probes; see 02-RUNBOOK.md §6.
 *
 * BUILTIN POOL (below, __COUNT__ hosts) — a bootstrap so the mechanism functions on
 * day one. It is honestly weaker in one specific way: real Tier-D targets are
 * registered by IP on VPS ASNs, while these are third-party domains on
 * academic, CDN, and hosting ASNs. AN ATTENTIVE ADVERSARY CAN SEPARATE THEM
 * BY SHAPE. That is a known, documented limit — not a claim of equivalence —
 * and it is why the operator pool exists. `poolHealth()` reports it and the
 * collector surfaces it to the operator.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  WHY AN UNREACHABLE CANARY MUST NEVER ACCUSE ANYONE
 * ───────────────────────────────────────────────────────────────────────────
 *
 * Whether any given host is reachable from inside Iran is a judgement here,
 * not a measurement. If a host in this list is in fact blocked in country,
 * every HONEST probe reports it down — and the naive detector would add
 * suspicion to every honest probe while the censor, who knows better, reports
 * it up and looks clean. The detector would run exactly backwards.
 *
 * So a down-report on a canary scores nothing on its own. It scores only when
 * ANOTHER slot independently reached the same host in the same window. See
 * collector-worker.js report(). Under-crediting is the safe direction and the
 * only acceptable one: a false positive here is a real person, under a
 * government that imprisons them, quietly losing the good nodes (I3).
 *
 * SELECTION RULES for entries in this list are documented in
 * tools/build-canary-pool.mjs and enforced by tools + tests.
 */
