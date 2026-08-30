# Verifying this tool — English source text

> **STATUS: this is the English source. The Persian translation in
> `docs/VERIFY.fa.md` is a DRAFT that has NOT been reviewed by a native
> speaker. Do not publish it to users until it has been. See I10.**

Anyone can check that the copy of this tool they are running is the real one,
and that the server is not singling them out. You should. A circumvention tool
that asks to be trusted without offering a way to check is indistinguishable
from a honeypot, and you are right to assume the worst until you can verify.

## 1. Check the application you installed

Compare the signature on the release against the published signing key. The key
is published through more than one independent channel on purpose: if two
channels disagree, something is wrong and you should not install it.

```
# The published release hash should match the file you downloaded.
sha256sum <the file you downloaded>
```

## 2. Check that you are being given the same keys as everyone else

The server issues credentials under a key. If it gave *you* a different key from
everyone else, it could recognise you later. It cannot do this without being
caught, but catching it requires someone to look.

```
node tools/verify-commitment.mjs --key <PUBLISHED OPERATOR KEY> \
     https://<the server>/api/keys https://<a mirror>/keys.json
```

- **`all copies at the same serial are byte-identical`** — good. Everyone is
  getting the same keys.
- **`EQUIVOCATION DETECTED`** — the operator has published two different
  documents. This is serious. Stop using the tool and report it publicly,
  including both hashes the tool printed.
- **A source is unreachable** — probably censorship of that mirror, not an
  attack on you. The check still works with the sources you can reach.

The key you pass with `--key` must come from the published release, **not** from
the server you are checking. Verifying a document against a key handed to you by
the same party proves nothing.

## 3. What this does and does not protect

**It does protect you** against a server that has been broken into. Whoever
controls the server cannot make your app accept a key made for you alone,
because the signing key is kept offline, on a different machine.

**It does not protect you** against the people running the project, if they
choose to act against you. They hold the offline key. What it does is make that
choice detectable by anyone who compares copies — which is why the check above
matters, and why it should not only be us running it.

**Nothing here protects you if your phone is taken from you.** No network tool
can. Assume that anything on your device can be read by whoever holds it.
