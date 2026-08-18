#!/usr/bin/env python3
"""
verify-manifest.py — cross-implementation check for I-defect-3.

The collector signs work manifests with Ed25519 inside the Cloudflare Workers
runtime. 04-STATUS.md 2.3 recorded that support as ASSUMED. Verifying that
signature with the same library that produced it would prove nothing, so this
checks a real workerd-produced signature against TWO independent verifiers:

  1. the vendored pure-Python Ed25519 in deploy/probe-agent.py — the code that
     actually runs on a volunteer's phone, with no dependencies;
  2. python-cryptography — an audited reference implementation.

If manifest signing silently failed, the probe network never starts and the
agent correctly refuses every manifest. Volunteers inside Iran are the people
who would find that out.

Input is the artifact written by test/collector.test.mjs.

    node test/collector.test.mjs && python3 test/verify-manifest.py
"""
import base64
import importlib.util
import json
import os
import sys

ARTIFACT = os.environ.get("MANIFEST_ARTIFACT", "/tmp/tk-manifest-artifact.json")
HERE = os.path.dirname(os.path.abspath(__file__))

failures = []


def check(ok, label, detail=""):
    mark = "\033[32m✓\033[0m" if ok else "\033[31m✗\033[0m"
    suffix = f"  \033[90m{detail}\033[0m" if detail else ""
    print(f"  {mark} {label}{suffix}")
    if not ok:
        failures.append(label)


def load_agent():
    """Import probe-agent.py without running its main loop."""
    path = os.path.join(HERE, "..", "probe-agent.py")
    spec = importlib.util.spec_from_file_location("probe_agent", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["probe_agent"] = mod      # @dataclass resolves types via sys.modules
    spec.loader.exec_module(mod)
    return mod


def main():
    if not os.path.exists(ARTIFACT):
        print(f"missing artifact {ARTIFACT} — run test/collector.test.mjs first", file=sys.stderr)
        return 1

    with open(ARTIFACT) as fh:
        art = json.load(fh)

    pub = base64.b64decode(art["operator_pubkey"])
    body = art["manifest"].encode()
    sig = base64.b64decode(art["signature"])

    print("\n\033[1mI-defect-3 — Ed25519 signature from workerd, verified independently\033[0m")
    check(len(pub) == 32, "operator public key is 32 raw bytes", f"{len(pub)} bytes")
    check(len(sig) == 64, "signature is 64 raw bytes", f"{len(sig)} bytes")

    agent = load_agent()
    check(agent.ed25519_verify(pub, body, sig),
          "vendored pure-Python verifier in probe-agent.py accepts the signature")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    def reference(pubkey, message, signature):
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    check(reference(pub, body, sig),
          "python-cryptography accepts the same signature")

    targets = json.loads(art["manifest"]).get("targets", [])
    check(len(targets) > 0, f"the signed manifest carries {len(targets)} targets")

    print("\n\033[1madversarial — every one of these MUST be rejected\033[0m")

    tampered = body + b" "
    check(not agent.ed25519_verify(pub, tampered, sig),
          "agent rejects a manifest whose body was modified")
    check(not reference(pub, tampered, sig),
          "reference rejects a manifest whose body was modified")

    # Flip one bit inside the target list — the realistic attack is a changed
    # host, not appended whitespace.
    doc = json.loads(art["manifest"])
    doc["targets"][0]["host"] = "attacker.example"
    swapped = json.dumps(doc).encode()
    check(not agent.ed25519_verify(pub, swapped, sig),
          "agent rejects a manifest with a substituted target host")

    wrong = bytearray(pub)
    wrong[0] ^= 0x01
    check(not agent.ed25519_verify(bytes(wrong), body, sig),
          "agent rejects a signature under a different operator key")
    check(not reference(bytes(wrong), body, sig),
          "reference rejects a signature under a different operator key")

    bad_sig = bytearray(sig)
    bad_sig[63] ^= 0x01
    check(not agent.ed25519_verify(pub, body, bytes(bad_sig)),
          "agent rejects a signature with a flipped bit")

    check(not agent.ed25519_verify(pub, body, sig[:32]),
          "agent rejects a truncated signature")
    check(not agent.ed25519_verify(pub[:16], body, sig),
          "agent rejects a malformed public key")

    if failures:
        print(f"\n\033[31m{len(failures)} check(s) FAILED\033[0m")
        for f in failures:
            print(f"   - {f}")
        return 1
    print("\n\033[32mall checks passed — Ed25519 signing works in the Workers runtime\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
