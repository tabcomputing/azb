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
    github: silicon-circus/azb
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
against RFC 8032 test vectors (`crystal spec`).
