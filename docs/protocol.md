# AZB1 request signing protocol

Every API request except `GET /health` must be signed by the calling
site's Ed25519 private key. Azooka Bay verifies with the registered
public key — it never holds anything capable of producing a signature.

Reference implementation: the PUBLIC `azb` shard
(github.com/tabcomputing/azb) — sites written in Crystal depend on it
and use `AzookaBay::Signing` directly. The server depends on the same
shard, so a client's canonical string is byte-identical to the
verifier's by construction. (The algorithm is public by design; the
secret is the key.)

## Headers

| Header | Value |
|---|---|
| `X-AZB-Site` | site id (`pirate-ship`) |
| `X-AZB-Key` | key id of the signing key (`pirate-ship-20260726-b0c3`) |
| `X-AZB-Timestamp` | unix seconds, decimal |
| `X-AZB-Nonce` | single-use random token (e.g. 32 hex chars from a CSPRNG) |
| `X-AZB-Signature` | base64 Ed25519 signature over the canonical string |

## Canonical string

Newline-joined, signed as UTF-8 bytes:

```
AZB1 \n site_id \n key_id \n METHOD \n path \n sha256(body) \n timestamp \n nonce
```

- `METHOD` — uppercase HTTP method.
- `path` — exactly as sent, **including the query string** (`/v1/valuables?user_id=...`).
- `sha256(body)` — lowercase hex digest of the raw request body
  (`e3b0c442...` for an empty body).
- Field alphabets are strict; violations fail signing/verification rather
  than being escaped:
  - site_id / key_id / nonce: `[A-Za-z0-9._:-]{1,128}`
  - method: `[A-Z]{3,10}`
  - path: starts with `/`, no whitespace

## Client procedure

1. Compute the SHA-256 of the body you will send.
2. Take the current unix time and a fresh random nonce.
3. Build the canonical string, sign with your Ed25519 private key,
   base64-encode the 64-byte signature.
4. Send the five headers with the request.

Never reuse a nonce. Never sign anything other than the exact bytes you
send — any proxy that rewrites the body or path will break the signature
(that is the point).

## Server verification order

1. Header presence and shape — garbage never touches the database.
2. Timestamp freshness — |now − timestamp| ≤ **300 s**.
3. Site + key lookup — site `active`; key unrevoked, inside its
   `not_before`/`not_after` window.
4. Signature verification against the canonical string rebuilt from the
   request actually received.
5. Nonce consumption — atomic insert; a seen nonce is a replay. Consumed
   only *after* the signature proves origin, so an outsider cannot poison
   nonces.

All failures return one opaque `401 {"error":"unauthorized"}`. The
specific reason (missing headers, stale timestamp, unknown key, bad
signature, replay) is recorded in the audit log only — distinguishing
them in the response would hand an attacker an oracle. Recording is
budgeted, because unauthenticated volume is the attacker's to choose:
past the budget, failures are counted per reason rather than written one
row each (see architecture.md, "The audit log").

## Replay defence lifetime

Nonces are remembered for 1 hour (12× the skew window) and then reaped;
a request older than the skew window is already rejected as stale, so
the two mechanisms overlap with margin.

## Key lifecycle

Multiple keys per site may be live at once (rotation overlap). Rotate by
adding a new key, deploying it, then revoking the old — in that order.
A public key can never serve two sites and can never be re-registered
once revoked (enforced by uniqueness).
