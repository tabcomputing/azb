# azb

Client library for the **Azooka Bay** AZB1 signed-request protocol —
Ed25519 signing/verification bound to the system OpenSSL, and the
canonical request string, shared byte-for-byte with the server's
verifier because the server depends on this same shard.

Azooka Bay is a private identity/accounting service; this shard contains
only what a relying site needs to talk to it. The algorithm is public by
design ([Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)) —
the secret is your site's private key, never the protocol.

## Install

```yaml
dependencies:
  azb:
    github: tabcomputing/azb
```

## Sign a request

```crystal
require "azb"

key = AzookaBay::Ed25519::SigningKey.new(seed_bytes) # 32-byte seed
ts = Time.utc.to_unix
nonce = AzookaBay::Signing.generate_nonce
signature = AzookaBay::Signing.sign(
  key, site_id, key_id, "POST", "/v1/spend", body, ts, nonce)
# send with headers X-AZB-Site, X-AZB-Key, X-AZB-Timestamp,
# X-AZB-Nonce, X-AZB-Signature — see docs/protocol.md
```

- [docs/protocol.md](docs/protocol.md) — the AZB1 wire protocol
- [docs/api.md](docs/api.md) — endpoint reference

No dependencies; Crystal stdlib + system OpenSSL (>= 1.1.1). Validated
against RFC 8032 test vectors (`crystal spec`). Links cleanly alongside
`openssl_ext`/`jwt` (azb declares no `EVP_PKEY_free`; keys are
process-lifetime objects — construct once, reuse; verifiers should cache
per public key).

## Transport guarantees

One call is **one request** — the client removes Crystal's stdlib
behavior of silently retrying an `IO::Error` with the same request,
which would replay the nonce (an opaque 401) after work may already
have been done. A failed call raises `TransportError` (`timeout?` tells
you whether the request may have reached the server); retrying is the
caller's choice, always freshly signed. Retries of mutating calls are
safe when you reuse the same `idempotency_key`. `read_timeout`
(default 10s) bounds the whole call.

## Client

`AzookaBay::Client` wraps the protocol in typed calls, so a site does not
reimplement signed transport (and rediscover that the query string is part of the
signed path, or that nonces must never repeat).

```crystal
azb = AzookaBay::Client.from_env          # AZB_SITE_ID / AZB_KEY_ID / AZB_PRIVATE_KEY_SEED
azb.whoami                                 # proves creds, clock and signing end to end
azb.login_start("tom@example.com", redirect_path: "/midway")
login = azb.login_verify(token)            # from the magic link; first verify creates the user
login = azb.login_verify_code("tom@example.com", typed)  # or the typed code ("Magic Word"), server v0.7.0+
azb.user(login.user_id).active             # standing in this realm (server v0.6.0+), for session re-checks
azb.issue(user_id: login.user_id, asset: "bones", amount: 20,
          idempotency_key: "welcome-#{login.user_id}")
```

The seed may be raw bytes, 64 hex chars or base64 — a credential file's encoding
is decided by whatever wrote it, and a silent mismatch would otherwise surface as
an unexplainable 401 rather than a clear error at construction.

`Client::Error` carries the server's own `status` and `code`. Authentication
failures stay a single opaque `401 unauthorized` — the client does not guess at
or embellish them, because distinguishing them would hand an attacker the oracle
the server deliberately withholds. `#retryable?` marks the one code whose own
guidance is "retry later".
