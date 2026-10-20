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

# the site's own login look (server v0.8.0+): push it on every deploy;
# whole-set and idempotent, returns whether anything changed
azb.set_login("code", code_style: "digits", code_length: 6, label: "code")

# selling through Azooka Bay (server v0.9.0+): the site holds no Stripe key
catalog = azb.skus                          # the realm's SKUs this site may sell
co = azb.checkout(login.user_id, "coins-20", "buy-#{order_id}", ui: "embedded")
# page: mount Stripe's embedded Checkout with co.publishable_key + co.client_secret
# (or, for ui: "hosted", send the buyer to co.url)
status = azb.checkout_status(session_id)   # on the return page; poll while open?
status.user_id == login.user_id            # show it only to its buyer
status.settled?                            # credited once, on Stripe's word only
```

### A login file

A product keeps its login look in its own repo, by convention
`deploy/azb/login.yml`, with the vocabulary and email bodies as plain-text
files beside it (paths are relative to the YAML):

```yaml
method: code
code: { style: vocab, length: 4, vocab_file: magic-words.txt, separator: "-" }
label: Magic Word
email: { subject: "The scroll stirs for {site}", body_file: email-body.txt }
fallback_email: { subject: "The words fade", body_file: fallback-body.txt }
```

```crystal
require "azb/login_file"                      # opt-in: links libyaml
azb.set_login_file("deploy/azb/login.yml")    # on startup or deploy
```

`vocab:` and `body:` may be inline instead (not both). The file is strict: an
unknown or repeated key, or a second YAML document, is an error. Pass
`LoginFile.load(path, confine: true)` when the reader isn't the file's author:
it then reads only files inside the YAML's own directory. The Azooka Bay operator can apply the same file with
`azookabay-enroll login --site <id> --file deploy/azb/login.yml`.

The seed may be raw bytes, 64 hex chars or base64 — a credential file's encoding
is decided by whatever wrote it, and a silent mismatch would otherwise surface as
an unexplainable 401 rather than a clear error at construction.

`Client::Error` carries the server's own `status` and `code`, and its message
includes the server's reason when the server gives one (as for
`invalid_login_settings`). Authentication failures stay a single opaque
`401 unauthorized` — the client does not guess at or embellish them, because
distinguishing them would hand an attacker the oracle the server deliberately
withholds. `#retryable?` marks the one code whose own guidance is "retry later".
