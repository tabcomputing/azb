# API reference

All endpoints except `GET /health` require an AZB1 signature (see
`protocol.md`). Requests and responses are JSON. Authentication failures
are always an opaque `401 {"error":"unauthorized"}`; errors below are
post-authentication. Malformed JSON bodies get `400 {"error":"bad_json"}`.

## Idempotency

Every mutating call takes a caller-chosen `idempotency_key` (printable
ASCII, 1–128 chars), scoped per site. Retrying the same key returns the
**original** result with `"replay": true` — a timed-out call is always
safe to retry. Reusing a key with *different* parameters is a client bug
and gets a loud `422 {"error":"idempotency_mismatch"}`, never a silent
wrong answer.

---

## GET /health

Unsigned liveness probe. → `200 {"ok":true}`

## GET /v1/whoami

Signed no-op proving the full authentication path.
→ `200 {"site":"pirate-ship","key":"pirate-ship-20260726-b0c3"}`

## POST /v1/login/start

Mint a magic-link token and email it, branded as the calling site.

```json
{"email": "tom@example.com", "redirect_path": "/midway", "request_ip": "203.0.113.9"}
```
`redirect_path` and `request_ip` (the end user's IP as seen by the site)
are optional.

→ `202 {"ok":true}` — **always**, whether the address has an account,
is new, or is rate-limited (3 sends per email per site per 15 min,
silently). No enumeration oracle. The user record is *not* created here.

| Error | Status | Meaning |
|---|---|---|
| `bad_email` | 400 | not an email address |
| `bad_redirect_path` | 400 | must start with `/`, no whitespace |
| `login_not_configured` | 500 | site has no `link_base_url`, or no From resolves (site override and realm default both empty) |
| `email_failed` | 502 | mail provider refused; retry later |

The emailed link is `<site.link_base_url>?token=<token>`, valid 15
minutes, single-use, bound to the requesting site. Only the token's
SHA-256 is stored.

## POST /v1/login/verify

Redeem the token from the link (the site extracts it from its landing
route and calls this over the backchannel).

```json
{"token": "aB3xK9..."}
```

→ `200 {"user_id":"<uuid>","email":"tom@example.com","redirect_path":"/midway"}`

First verified login **creates** the user. The site then sets its own
session; Azooka Bay plays no further part in the session.

| Error | Status | Meaning |
|---|---|---|
| `invalid_token` | 401 | unknown, expired, consumed, or minted for another site — deliberately indistinguishable |
| `user_inactive` | 403 | account suspended or closed |

## POST /v1/issue

Mint asset to a user. Requires `may_issue` on the asset.

```json
{"user_id": "<uuid>", "asset": "bones", "amount": 20,
 "idempotency_key": "stripe_cs_123", "kind": "purchase",
 "description": "$1.00 -> 20 bones", "metadata": {"stripe_session": "cs_123"}}
```
`kind`: `"purchase"` (issued for payment — reconciles against Stripe) or
`"grant"` (winnings, promos, bonuses; the default). Creates the user's
account for the asset on first grant.

→ `200 {"transaction_id": 42, "balance": 20, "replay": false}`

| Error | Status |
|---|---|
| `bad_user_id` / `bad_amount` / `bad_idempotency_key` / `bad_kind` | 400 |
| `capability_denied` | 403 |
| `user_inactive` | 403 |
| `unknown_user` | 404 |
| `idempotency_conflict` | 409 |
| `idempotency_mismatch` | 422 |

## POST /v1/spend

One-call debit — the arcade path. Requires `may_spend`.

```json
{"user_id": "<uuid>", "asset": "bones", "amount": 1,
 "idempotency_key": "play_9f3a", "description": "arcade play"}
```

→ `200 {"transaction_id": 43, "balance": 19, "replay": false}`

Errors as for issue, minus `bad_kind`, plus:

| Error | Status |
|---|---|
| `insufficient_balance` | 409 |

## POST /v1/reverse

Compensating transaction: posts the exact negation of the original's
entries. A site may reverse **only transactions it created** — creation
authority implies reversal authority, nothing wider.

```json
{"transaction_id": 43, "idempotency_key": "play_9f3a_refund",
 "reason": "game failed to start"}
```

→ `200 {"transaction_id": 44, "reversed_id": 43, "replay": false}`

| Error | Status | Meaning |
|---|---|---|
| `bad_idempotency_key` | 400 | |
| `unknown_transaction` | 404 | nonexistent **or another site's** — deliberately indistinguishable |
| `already_reversed` | 409 | nothing may be reversed twice |
| `insufficient_balance` | 409 | e.g. reversing an issue the user already spent |
| `cannot_reverse_reversal` | 422 | re-post instead |
| `idempotency_mismatch` | 422 | |

## POST /v1/award

Place a collectible on a user's shelf. No journal involvement. Any venue
in the collectible's realm may award; the collectible is addressed by
code within the calling site's realm.

```json
{"user_id": "<uuid>", "collectible": "kraken-slayer",
 "idempotency_key": "badge_881", "metadata": {"score": 5000}}
```
`copy_no` optional — omitted, the next free slot is taken (capped at the
collectible's `max_per_user`).

→ `200 {"award_id": 7, "collectible": "kraken-slayer", "copy_no": 1, "replay": false}`

| Error | Status |
|---|---|
| `bad_user_id` / `bad_idempotency_key` / `bad_copy_no` | 400 |
| `user_inactive` | 403 |
| `unknown_collectible` | 404 (includes other realms' collectibles) |
| `unknown_user` | 404 |
| `award_limit_reached` / `already_awarded` | 409 |
| `idempotency_mismatch` | 422 |

## GET /v1/valuables?user_id=<uuid>

Everything the user owns, through the calling site's realm wall.

→ `200`
```json
{"user_id": "<uuid>", "realm": "silicon-circus",
 "balances": {"bones": 25, "emeralds": 50},
 "collectibles": [
   {"code": "kraken-slayer", "copy_no": 1,
    "awarded_at": "2026-07-29T12:00:00Z", "metadata": {"score": 5000}}]}
```

| Error | Status |
|---|---|
| `missing_user_id` / `bad_user_id` | 400 |
| `unknown_user` | 404 |

Inactive users are readable (their property record persists); only
transacting is blocked.

## GET /v1/profile?user_id=<uuid>

Realm-scoped shared metadata — what every venue in the realm agrees on
about a user (display name, level, preferences). Scoped to the calling
site's realm; other realms' entries are invisible.

→ `200 {"user_id":"<uuid>","realm":"silicon-circus","profile":{"display_name":"Captain Tom","level":3}}`

| Error | Status |
|---|---|
| `missing_user_id` / `bad_user_id` | 400 |
| `unknown_user` | 404 |

Inactive users are readable, like valuables.

## PUT /v1/profile

Merge-patch: each key in `entries` is set to its value; an explicit JSON
`null` deletes the key. Values are arbitrary JSON. Naturally idempotent —
no idempotency key.

```json
{"user_id": "<uuid>", "entries": {"display_name": "Captain Tom", "old_key": null}}
```

→ `200 {"user_id":"<uuid>","set":["display_name"],"deleted":["old_key"]}`

Keys: `[A-Za-z0-9_.-]{1,64}`, at most 64 per request. Not for app-private
rich data (that stays in the app's own database) and not for valuables.
The audit log records which keys changed, never the values.

| Error | Status |
|---|---|
| `bad_user_id` / `bad_key` / `no_entries` / `too_many_keys` | 400 |
| `user_inactive` | 403 (writes need an active user; reads do not) |
| `unknown_user` | 404 |

## Not yet implemented

`POST /v1/exchange` — the cross-realm bridge (e.g. circus tokens ↔
Onboard credits). The ledger already supports it end to end; the endpoint
waits for the first consumer. See TODO.md.
