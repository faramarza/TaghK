/**
 * harness.mjs — the smallest thing that can run a test.
 *
 * No framework on purpose. This tree ships to people whose safety depends on
 * being able to read it, and every dependency is one more thing an auditor has
 * to trust and one more supply-chain path into a circumvention client (I9).
 */
let failures = [];
let count = 0;

export function section(title) {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}

export function check(ok, label, detail = '') {
  count++;
  const mark = ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
  console.log(`  ${mark} ${label}${detail ? `  \x1b[90m${detail}\x1b[0m` : ''}`);
  if (!ok) failures.push(label);
}

export const eq = (got, want, label) =>
  check(got === want, label, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);

/** Assert that something throws. A suite with no failing-input cases proves nothing. */
export async function throws(fn, label) {
  try { await fn(); check(false, label, 'did not throw'); }
  catch (e) { check(true, label, e.message.slice(0, 70)); }
}

export function summary() {
  if (failures.length) {
    console.log(`\n\x1b[31m${failures.length} of ${count} checks FAILED\x1b[0m`);
    for (const f of failures) console.log(`   - ${f}`);
    process.exit(1);
  }
  console.log(`\n\x1b[32mall ${count} checks passed\x1b[0m`);
}
