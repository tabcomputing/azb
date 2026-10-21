# API reference

All endpoints except `GET /health` and Stripe's webhook require an AZB1
signature (see `protocol.md`). Requests and responses are JSON. Authentication failures
are always an opaque `401 {"error":"unauthorized"}`; errors below are
post-authentication. Malformed JSON bodies get `400 {"error":"bad_json"}`.

## Realm membership

Every endpoint that names a user (`issue`, `spend`, `balance`,
`valuables`, `profile`, `vault`, `user`, `checkout`) acts within the calling site's
**realm**, and the user must be a **member** of that realm.
- A user becomes a member at their first verified login through one of
  the realm's sites (`/v1/login/verify`).
- **A non-member is reported exactly like an unknown user:**
  `404 {"error":"unknown_user"}`. No realm can probe whether a person has
  an account in another.
- **`user_inactive` (403)** means the user is suspended or closed either
  network-wide or in *this* realm. A suspension in one realm leaves the
  user's other realms untouched.
- Reads still answer for inactive members and carry a `hold`; writes
  refuse.

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

Signed no-op proving the full authentication path — and the calling
site's own standing, so a deployment's `/health` can report what is
*wired* (grants in place) rather than merely configured. A site sees
only its own grants, never another's. `version` is the running Azooka
Bay's (since v0.9.2), so a deploy can confirm what it put in place.

→ `200 {"site":"pirate-ship","key":"pirate-ship-20260726-b0c3",
        "realm":"silicon-circus","capabilities":{"scc":["issue","spend"]},
        "version":"0.9.2"}`

Permissions are `issue`, `spend`, `exchange` and `sell`.

## POST /v1/login/start

Email the user a way in, branded as the calling site. What the email
carries depends on the site's **login method** (set by the site itself,
[`PUT /v1/site/login`](#put-v1sitelogin), or by the operator,
`azookabay-enroll login`):

- `link` (the default): a magic link;
- `code`: a typed code, which the user enters on the page that asked (see
  [Typed login codes](#typed-login-codes-the-magic-word));
- `both`: the code and a link; using either kills the other.

After 3 wrong codes for an address at a code site within 24 hours, that
address gets **a link instead** at that site until the failures age out
(see [the fallback](#the-fallback-links-after-3-wrong-codes)). So every
login-capable site needs a link landing page, code-only sites included.

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
| `bad_redirect_path` | 400 | must start with `/`, no whitespace, and not `//`/`/\\` (protocol-relative open-redirect guard) |
| `login_not_configured` | 500 | a link-capable site has no `link_base_url`, a code-capable site has no code style, or no From resolves (site override and realm default both empty) |
| `email_failed` | 502 | mail provider refused; retry later |
| `login_codes_unavailable` | 503 | the site uses typed codes and the server has no `AZB_LOGIN_CODE_KEY` |

The emailed link is `<site.link_base_url>?token=<token>`, valid 15
minutes, bound to the requesting site. Only the token's SHA-256 is
stored. Redeemable up to the site's `login_max_redemptions` (default 1 =
single-use) within that lifetime — raise it to tolerate corporate mail
scanners (Safe Links/Proofpoint/Mimecast) that GET the link before the
human clicks. The short expiry stays the real control; and the better
fix is a landing page that redeems on a user gesture / JS, which
scanners do not execute.

## POST /v1/login/verify

Redeem the token from the link (the site extracts it from its landing
route and calls this over the backchannel):

```json
{"token": "aB3xK9..."}
```

or the typed code, with the email it was sent to:

```json
{"email": "tom@example.com", "code": "Ali Ka Thul Zam Vex"}
```

→ `200 {"user_id":"<uuid>","email":"tom@example.com","redirect_path":"/midway"}`

First verified login **creates** the user (one account per email,
network-wide), and a verified login makes the user a **member** of the
site's realm, if they were not already. The site then sets its own
session; Azooka Bay plays no further part in the session.

| Error | Status | Meaning |
|---|---|---|
| `missing_params` | 400 | neither `token` nor both `email` and `code` |
| `invalid_token` | 401 | unknown, expired, over the site's redemption ceiling, never mailed as a link, or minted for another site — deliberately indistinguishable |
| `invalid_code` | 401 | wrong, used, expired, the address has had 3 wrong codes at this site in 24 hours, no login pending, mailed under a replaced server key, or another site's — deliberately indistinguishable |
| `user_inactive` | 403 | account suspended or closed, network-wide or in this site's realm |
| `login_codes_unavailable` | 503 | a typed code, and the server has no `AZB_LOGIN_CODE_KEY` |

### Typed login codes (the Magic Word)

A magic link signs in only the browser that opens it. In practice that
means a stray new tab, the wrong browser when a phone's mail app opens it,
and a target for corporate mail scanners. A **typed code** works on the
page that asked, on any device. A code-only site sends no link, except
as the fallback below.

- **Azooka Bay generates every code**; the site chooses its look:
  - digits (6–10): `482913`. Give your input field
    `autocomplete="one-time-code"` so iOS and macOS can offer the code
    from Mail;
  - the site's own **vocabulary** (syllables or words), N picked at random
    and joined by a separator: `ali-ka-thul-zam-vex`. The flavour is the
    site's; the strength is enforced by AB (at least a million possible
    codes). The vocabulary must be prefix-free (no entry may begin
    another, as `in` begins `into`), since codes are compared without
    their separators.
- **Typing is forgiving:** case, spaces, hyphens and punctuation are
  ignored.
- **Guarded:**
  - one use, for the site that asked, within the login's 15 minutes;
  - at most 3 wrong guesses per address and site in 24 hours: then codes
    are refused and links take over (below). Guesses for one address and
    site are taken one at a time, so parallel requests can't exceed the
    cap. A wrong guess counts once for each code still live, so a user who
    asked for three emails can fall back after one wrong guess;
  - every failure is the same `invalid_code`, after the same work;
  - stored only as an HMAC under a server key the database never holds,
    so a leaked database row can't be brute-forced.
- **The email** shows the code in a large block that a single tap selects
  where the mail client allows it (Apple Mail, iOS). A real copy button is
  impossible because mail clients strip script. The subject and body can
  be the site's own (in character), and Azooka Bay always adds its safety
  lines ("never share your …", "didn't ask for this?").
- With method `both`, redeeming the link kills the code and vice versa.
  If you also raise `login_max_redemptions` for mail scanners, redeem
  links on a user gesture or in JavaScript, or a scanner's prefetch will
  kill the user's code.

### The fallback: links after 3 wrong codes

Three wrong codes for one address at a site within 24 hours switch that
address to **links** at that site until those failures are 24 hours old.
The site changes nothing: its "send me a new code" button calls
`/v1/login/start` as usual (still `202 {"ok":true}`), and the email now
carries a link instead of a code. Redeem it like any magic link.

- **Why:** guessing stays capped at 3 tries a day per address and site,
  yet nobody can lock a player out by guessing wrong on purpose. A link
  can't be guessed; the worst an attacker can do is push a player onto
  links for a day.
- **Your landing page must redeem on a user gesture or in JavaScript,
  never on the bare GET.** Mail scanners (Safe Links, Mimecast,
  Proofpoint) open links before the human does, and they don't run
  script. A landing page that redeems on GET lets the scanner spend every
  fallback link, so an attacker who forces the fallback would lock out a
  player behind such a scanner after all.
- **The email** can be the site's own (`login --fallback-subject`,
  `--fallback-body-file`; placeholders `{site}` `{label}` `{link}`
  `{minutes}`, no `{code}`). On a vocabulary site, the link shows as a
  fresh word from the vocabulary, underlined, with no URL: touched, not
  typed (typing it does nothing). A digit site shows a "Log in" button.
  The plain-text part of the email always shows the full URL.
- **The stray tab:** the link opens a new tab. Your landing page and the
  page that asked are the same site, so the landing page can tell the
  waiting tab "logged in" (a `BroadcastChannel`, or a `storage` event),
  and say "you can close this tab". That works whenever the link opens in
  the same browser.

## PUT /v1/site/login

Set the calling site's **own login presentation** (server v0.8.0+): how
its players sign in and how its login emails read. This is the product's
design, so the product keeps it in its own repo and pushes it, typically
on every deploy. With azb, the usual way is a **login file**,
`deploy/azb/login.yml` (method and settings, with the vocabulary and
email bodies as text files beside it): `require "azb/login_file"`, then
`client.set_login_file("deploy/azb/login.yml")`; or `client.set_login(...)`
with the values. The operator can apply the same with
`azookabay-enroll login` (`--file` for a login file).

```json
{"method": "code",
 "code_style": "vocab", "code_length": 4, "separator": "-",
 "vocab": ["ka", "zo", "mi", "thul", "vex", "..."],
 "label": "Magic Word",
 "email_subject": "The scroll stirs for {site}",
 "email_body": "The ink resolves into words:\n\n{code}\n\nSpeak them at the gate within {minutes} minutes.",
 "fallback_subject": "The words fade",
 "fallback_body": "The words would not take. Touch them instead: {link}"}
```

| Field | |
|---|---|
| `method` | `link`, `code` or `both` (required) |
| `code_style`, `code_length` | `digits` with 6–10, or `vocab` with 2–12 entries per code (code methods only) |
| `vocab`, `separator` | the vocabulary (1–16 letters a-z each, prefix-free, at most 4096) and `-`, ` ` or `·` |
| `label` | what the email calls the code, 1–40 characters |
| `email_subject`, `email_body` | templates (see [Typed login codes](#typed-login-codes-the-magic-word)) |
| `fallback_subject`, `fallback_body` | the link-instead email's templates (code methods only) |

→ `200 {"changed": true}`, or `{"changed": false}` when it was already
so. **Whole-set:** an omitted field returns to its default (AB's default
email copy, label "code"), so always send the full presentation.

- Validated exactly as the operator's command is: at least a million
  distinct codes, a prefix-free vocabulary (its order doesn't matter),
  digits with no vocabulary or separator, a one-line label of up to 40
  characters, templates that carry what the method needs. AB always adds
  its own safety lines to the email.
- **Templates and the label can't contain web or email addresses**
  (`https://…`, `www.…`, `name@domain`, a bare `domain.tld` or an IP),
  including look-alike letters and dots, and including what placeholders
  assemble (`"Go to {label}.com"` is checked as the reader would see it).
  Mail apps turn addresses into links, and the only link in a login email
  is the one AB puts at `{link}`, on the site's own landing page. In prose,
  put a space after a period: `Speak.Now` reads as a domain. No control
  characters; valid UTF-8.
- A real change is audited (`site_login`, with the key that made it) with
  the templates' full text, so what the emails said stays on record; an
  unchanged push writes nothing. At most 30 changes per site per 24 hours.
- **Not settable here, by design:** the landing URL (`link_base_url`) and
  the From and reply-to addresses. A stolen site key that could change
  them could point login links at another server, or send mail as your
  verified domains; they stay with the operator.

| Error | Status | Meaning |
|---|---|---|
| `invalid_login_settings` | 400 | refused, with `message` saying why (e.g. `digits codes must be 6-10 long`) |
| `bad_json` | 400 | not JSON, or a field that isn't in the table above (e.g. `link_base_url`) |
| `too_many_changes` | 429 | over 30 changes in 24 hours; an unchanged push still answers 200 |

**If a site key is stolen**, the thief could use up the day's 30 changes
and leave the site's own corrective push refused. Revoke the key
(`azookabay-enroll revoke-key`), rotate, and have the operator apply the
product's login file (`azookabay-enroll login --site S --file …`), which
isn't rate-limited.

## POST /v1/issue

Mint asset to a user. Requires `may_issue` on the asset.

```json
{"user_id": "<uuid>", "asset": "scc", "amount": 20,
 "idempotency_key": "stripe_cs_123", "kind": "purchase",
 "description": "$5.00 -> 20 circus tokens", "metadata": {"stripe_session": "cs_123"}}
```
`kind`: `"purchase"` (issued for payment — reconciles against Stripe) or
`"grant"` (winnings, promos, bonuses; the default). Creates the user's
account for the asset on first grant.

In a realm that sells through Azooka Bay (a `stripe:` block in its realm
file), purchases come only from Stripe's word (see Payments below), and
`kind: "purchase"` here is refused with `403 purchase_via_checkout`.
Grants are unaffected.

→ `200 {"transaction_id": 42, "balance": 20, "replay": false}`

| Error | Status |
|---|---|
| `bad_user_id` / `bad_amount` / `bad_idempotency_key` / `bad_kind` | 400 |
| `capability_denied` | 403 |
| `purchase_via_checkout` | 403 |
| `user_inactive` | 403 |
| `unknown_user` | 404 |
| `idempotency_conflict` | 409 |
| `idempotency_mismatch` | 422 |

## POST /v1/spend

One-call debit — the arcade path. Requires `may_spend`.

```json
{"user_id": "<uuid>", "asset": "scc", "amount": 1,
 "idempotency_key": "play_9f3a", "description": "arcade play"}
```

→ `200 {"transaction_id": 43, "balance": 19, "replay": false}`

Errors as for issue, minus `bad_kind`, plus:

| Error | Status |
|---|---|
| `insufficient_balance` | 409 |

## POST /v1/reverse

Deliberately not gated on the user's membership or standing: a site
reverses only its own transactions, and correcting a suspended member's
transaction is exactly what reversal is for.

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

## GET /v1/balance?user_id=<uuid>

Hot-path display read — every asset the user holds in the calling site's
realm, **balances only**. No `flows` aggregate and no `hold`, so it is
flat regardless of ledger history: a handful of indexed rows. This is the
arcade cabinet wallet.

→ `200 {"user_id":"<uuid>","realm":"silicon-circus","balances":{"scc":22}}`

For the coin drop itself use **`/v1/spend`** — attempting the spend IS
the balance check (race-free), and its response already carries the new
balance. Reach for `/v1/balance` only to paint a number frequently.
Unlike other endpoints, a *successful* balance read is not audited
per-hit (it is a display poll); its denials are.

| Error | Status |
|---|---|
| `missing_user_id` / `bad_user_id` | 400 |
| `unknown_user` | 404 |

## GET /v1/valuables?user_id=<uuid>

Everything the user owns, through the calling site's realm wall — plus
`flows`: the signed lifetime sum of the user's entries per asset, grouped
by transaction kind. Raw journal truth, uninterpreted (reversals appear
under `reversal` as signed nets). This is the input for venue-side
loyalty math ("how much has this account genuinely purchased"):
discount ladders are venue policy computed from
`flows["<asset>"]["purchase"]`; the ledger only reports what happened.

→ `200`
```json
{"user_id": "<uuid>", "realm": "silicon-circus",
 "hold": null,
 "balances": {"scc": 25},
 "flows": {"scc": {"purchase": 20, "grant": 5, "spend": -1, "reversal": 1}}}
```

| Error | Status |
|---|---|
| `missing_user_id` / `bad_user_id` | 400 |
| `unknown_user` | 404 |

Inactive users are readable (their property record persists); only
transacting is blocked. **`hold`** is the side-effect-free way to learn a
user is no longer good: `null` (or absent, on older servers) when active;
otherwise `{"message": <text>?, "url": <url>?}`. Its mere presence is the
signal "inactive — stop"; the message/url are copy Azooka Bay authored
**for the user**, rendered verbatim by the site, which never learns the
reason (suspended vs closed, or why). A site polling this to re-validate
long-lived sessions should fail OPEN if Azooka Bay is unreachable — an
outage must never sign the network out.

## GET /v1/user?user_id=<uuid>

A member's standing in the calling site's realm: may they act, and if
not, the copy to show them. Use it to re-check a session cheaply (it
reads one membership row).

→ `200 {"user_id":"<uuid>","realm":"silicon-circus","active":true,"hold":null,"member_since":"2026-10-01T12:00:00Z"}`

When inactive, `"active": false` and `hold` is
`{"message": ..., "url": ...}`. That copy is authored by Azooka Bay
*for the user*; render it verbatim. Sites learn **whether**, never
**why**: suspended and closed, network-wide or in this realm, all look
the same.

Like `/v1/balance`, a *successful* read is a display poll and is not
audited per-hit; its denials are.

| Error | Status |
|---|---|
| `missing_user_id` / `bad_user_id` | 400 |
| `unknown_user` | 404 (no such user, or not a member of this realm) |

## GET /v1/profile?user_id=<uuid>

Realm-scoped shared metadata — what every venue in the realm agrees on
about a user (display name, level, preferences). Scoped to the calling
site's realm; other realms' entries are invisible.

→ `200 {"user_id":"<uuid>","realm":"silicon-circus","hold":null,"profile":{"display_name":"Captain Tom","level":3}}`

`hold` is the same side-effect-free inactive signal documented under
`/v1/valuables` — `null`/absent when active, an object otherwise.

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

## GET /v1/stats

Aggregate activity for the **calling site only** — the numbers an admin
panel's pulse wants. Never a sister site's, never another realm's, and
counts only: no emails, no user ids. Read from the audit log, so it
covers everything since the site was enrolled.

→ `200`
```json
{"site": "silicon-circus-web", "as_of": "2026-09-29T23:10:00Z",
 "windows": {
   "15m": {"users_logged_in": 4, "new_users": 1, "login_emails_sent": 5,
           "login_emails_failed": 0, "login_links_rejected": 1, "users_transacting": 3},
   "24h": {...}, "7d": {...}, "30d": {...}}}
```

| Field | Meaning |
|---|---|
| `users_logged_in` | distinct users who completed a login here in the window |
| `new_users` | of those, users whose **first ever** login here falls in the window (an account made at another realm's door is still new here) |
| `login_emails_sent` | magic-link emails actually handed to the mail provider |
| `login_emails_failed` | the provider refused the send (`502 email_failed`) — nonzero is an alarm |
| `login_links_rejected` | redemptions of dead links: expired, already used, or never valid |
| `users_transacting` | distinct users with a successful issue or spend here (idempotent replays excluded — a retry moves no value) |

**It cannot say who is logged in *right now*.** The session belongs to the
site — Azooka Bay verifies the link and steps out — so "now" is the site's
own request traffic. The useful pairing: the site counts who it has seen
recently, and `users_logged_in` for the site's session lifetime is the
ceiling on how many people could hold a valid session (a site with
30-day cookies reads the `30d` window).

Throttled twice, per site: results are **cached for 60 s** (`as_of` is
the database time they were computed at; polling faster returns the same
numbers), and past **20 calls a minute** the site gets
`429 {"error":"rate_limited"}` with a `Retry-After` header. Both are per
server process (N instances allow N× the calls). Like `/v1/balance`, a
successful stats read is a display poll and is not audited per-hit; only
the first 429 in each window is. The query is capped at 5 s. If it fails
the site gets `503 {"error":"stats_unavailable"}` with a `Retry-After`,
and the failure is cached like a result: the next attempt happens after
the TTL, not on every call. Show your last good numbers meanwhile.

Before v0.4.4 ledger audit rows recorded the user id as the site spelled
it; a site that varied its spelling (case, hyphens) can be over-counted
in `users_transacting` for the first 30 days after upgrading.

| Error | Status |
|---|---|
| `rate_limited` | 429 |
| `stats_unavailable` | 503 |

## Payments: selling through Azooka Bay

A realm sells through Azooka Bay when its realm file has a `stripe:` block
and `skus:` (operations.md). A SKU is a bundle of one of the realm's
assets at a price. A site holding `sell` on an asset may open Stripe
Checkout sessions for the realm's SKUs of it. Azooka Bay opens the
session with the realm's own Stripe key, and **only Stripe's word makes a
purchase**: its signed webhook, or Azooka Bay reading the session back
itself. The site never issues purchased coins and never touches a Stripe
key.

The flow:
1. The shop page lists `GET /v1/skus`.
2. The buyer picks one; the site's server calls `POST /v1/checkout`. For
   `ui: "embedded"`, the page mounts Stripe's embedded Checkout with the
   returned `publishable_key` and `client_secret`; for `ui: "hosted"`, it
   sends the buyer to the returned `url`.
3. Stripe sends the buyer back to the realm's `return_url`, with the
   session id where the URL says `{CHECKOUT_SESSION_ID}`. The return page
   asks `GET /v1/checkout?session_id=…` every couple of seconds until the
   status is no longer `open`, and checks the `user_id` is the signed-in
   buyer's.
4. The coins are credited once, whichever comes first: the webhook, or
   that read. The browser coming back proves nothing by itself.

### GET /v1/skus

The realm's active SKUs of assets the calling site may sell, cheapest
first, and the publishable key the page mounts Stripe's form with. A
display read: not audited per hit.

→ `200 {"realm":"silicon-circus","publishable_key":"pk_live_…",
        "skus":[{"id":"coins-20","name":"20 Circus Coins","asset":"scc","quantity":20,"cents":500}]}`

`404 not_selling`: the realm doesn't sell through Azooka Bay.

### POST /v1/checkout

```json
{"user_id": "<uuid>", "sku": "coins-20", "ui": "embedded", "idempotency_key": "buy-7f3a"}
```

`ui`: `"embedded"` or `"hosted"` (the default). The user must be an active
member. Name, price and quantity are the SKU's at that moment; a later
price change doesn't touch an open checkout. Stripe's page takes a payment
for an hour; the buyer types their email there (Azooka Bay doesn't tell
sites members' addresses, and Stripe's page would). If the realm file sets
`terms`, the buyer must tick a box beside those words before paying. A
buyer has at most 5 checkouts live in a realm at once.

`redirect` (embedded only): `"always"` (the default) or `"if_required"`.
Stripe's embedded form sends the buyer on to the realm's `return_url` once
they've paid. With `"if_required"` it does so only after a payment method
that leaves the page (a bank's own site); otherwise the page carries on,
and Stripe.js calls its `onComplete`, where the page asks
`GET /v1/checkout` as a return page would. So a buyer mid-game isn't sent
out of it. The return page is still needed, for the methods that leave.

→ `200 {"payment_id": 12, "session_id": "cs_live_…", "client_secret": "cs_live_…_secret_…",
        "url": null, "publishable_key": "pk_live_…",
        "expires_at": "2026-10-21T18:03:22Z", "replay": false}`

`client_secret` is set for embedded checkouts, `url` for hosted ones. The
same idempotency key returns the same session (`"replay": true`) while
it's open, and finishes opening it if Stripe didn't answer the first time.
Once it's closed (paid, expired, failed), the key answers
`409 checkout_closed`: a new purchase takes a new key. A retry must ask
for the same user, SKU, `ui` and `redirect` (`422 idempotency_mismatch`),
and is checked like a new checkout: once the site's `sell` is revoked or
the buyer is suspended, it's refused.

| Error | Status |
|---|---|
| `bad_user_id` / `bad_idempotency_key` / `bad_ui` | 400 |
| `bad_redirect`: not `always` or `if_required`, or `if_required` on a hosted checkout | 400 |
| `capability_denied`: no `sell` on the SKU's asset | 403 |
| `user_inactive` | 403 |
| `unknown_sku` (not the realm's, or retired) / `unknown_user` / `not_selling` | 404 |
| `checkout_closed` | 409 |
| `idempotency_mismatch` | 422 |
| `too_many_checkouts`: the buyer has 5 live already | 429 |
| `stripe_refused`: Stripe said no (the server's log says why); this checkout is closed | 502 |
| `stripe_unreachable`: no answer from Stripe; retry under the same key | 502 |
| `payments_unavailable`: this server has no Stripe key for the realm | 503 |

### GET /v1/checkout?session_id=<cs_…>

Only the site that opened the checkout can see it, and only while the
buyer is a member of its realm (`404 unknown_user` once they aren't).

→ `200 {"session_id":"cs_live_…","user_id":"<uuid>","status":"settled","sku":"coins-20",
        "asset":"scc","quantity":20,"amount_cents":500,"currency":"usd",
        "transaction_id":88,"balance":120,"settled_at":"2026-10-21T17:04:51Z"}`

`user_id` is the buyer: a return page shows a purchase only to them (a
session id in a URL can be someone else's). `settled_at` is when Azooka Bay
recorded the payment (and credited it), usually seconds after the buyer
paid; it stays once the payment is refunded or charged back, and is null
for one never settled.

`status`:
- `open`: Stripe's page is live. Azooka Bay asks Stripe itself (at most
  once every 2 seconds per checkout, however often the page asks), so a
  late webhook doesn't keep the buyer waiting.
- `processing`: paid by a method that takes days to clear (a bank debit).
  The coins come when Stripe says it cleared; the page can stop asking.
- `settled`: paid and credited. `balance` is the buyer's balance of the
  asset.
- `expired`, `failed`: never paid.
- `mismatched`: paid, but not what was offered; nothing was credited, and
  it's the operator's to look into.
- `refunded`, `charged_back`: paid, then the money went back.

A display poll: not audited per hit (settling always is). Errors:
`400 bad_session_id`, `404 unknown_checkout`.

### Refunds and chargebacks

When Stripe reports a full refund or a dispute, Azooka Bay takes back what
the buyer still holds: the whole purchase reversed if they hold it all,
otherwise everything they hold of the asset, as an adjustment. The rest
is recorded on the payment as lost (spent before the money went back),
and the status becomes `refunded` or `charged_back`. A partial refund
changes no coins: it's audited for the operator to settle by hand. A
refund Stripe reports before the payment itself (events come in no set
order) is handled the same: the payment is credited first, then taken back.
Azooka Bay doesn't suspend the buyer; that's the realm's policy (the
operator's `member` command).

A purchase made on Stripe's word is Azooka Bay's own transaction, not the
site's: `POST /v1/reverse` can't undo it (`404 unknown_transaction`).

### POST /v1/stripe/webhook/<account>

Stripe's endpoint, not a site's: signed by Stripe (`Stripe-Signature`,
HMAC-SHA256 under the endpoint's signing secret), not by AZB1. Setting it
up is in operations.md.
- An account this server has no signing secret for: `404`.
- A bad signature, or one more than 5 minutes off: `400`.
- Otherwise: `200 {"received":true,"outcome":"handled"}` (or `"ignored"`).

The events it acts on are `checkout.session.completed`,
`checkout.session.async_payment_succeeded`,
`checkout.session.async_payment_failed`, `checkout.session.expired`,
`charge.refunded` and `charge.dispute.created`. Every one is idempotent,
since Stripe delivers at least once and in no promised order. Events for
checkouts Azooka Bay didn't open (another integration's sales on the same
account, whatever reference they carry) and events of the other mode
(test on a live server, or live on a test one) are ignored.

## Vault — safe deposit boxes (`/v1/vault`)

Small sensitive values a site keeps for a user: a birthday, a shipping
address, a token, your own ciphertext. **Opaque to Azooka Bay**: a value
is a string (1 byte to 16 KiB) that AB stores and returns byte for byte.
It never parses, validates, interprets, or logs it. What a box holds is
the site's business; AB's business is the vault:

- **Encrypted at rest.** AES-256-GCM with a fresh data key per value,
  each wrapped by a master key that lives only in the server's
  environment, never in the database or its backups. A database dump
  yields ciphertext.
- **Realm-scoped.** Boxes belong to the calling site's realm: a box
  written at Silicon Circus is invisible to Onboard, even under the same
  label.
- **Granted per label.** The label (`box`) is the site's choice
  (`[a-z0-9][a-z0-9_.-]{0,63}`). A site may read or write a label only
  with an operator grant (`azookabay-enroll vault-grant`), made with a
  signing key enrolled for vault use. Both are sealed with the vault's
  master key, so they cannot be forged in the database. Anything missing
  gives `403`, checked before the user is looked up, so the site learns
  nothing. A site's new signing key reaches the vault only once it is
  sealed: `rotate` does that at mint when the operator holds the vault key;
  otherwise the operator runs `azookabay-enroll vault-seal-key`.
- **Audited, without contents.** Every call is written to the audit log,
  with who, which label, and when. Values are never logged.
- **Deletable.** `DELETE` removes the box from the live database. Backups
  keep a sealed copy, which stays openable until the master key it was
  wrapped under is retired and destroyed.

Want AB unable to read a value even in principle? Seal it yourself before
the `PUT`; AB's encryption then wraps ciphertext it cannot open.

### PUT /v1/vault

```json
{"user_id": "<uuid>", "box": "birthday", "value": "1990-06-15"}
```
→ `200 {"user_id":"<uuid>","realm":"silicon-circus","box":"birthday","updated_at":"..."}`

Creates or replaces. Needs `write` on the label and an active user.

### GET /v1/vault?user_id=<uuid>&box=<label>

→ `200 {"user_id":"<uuid>","realm":"silicon-circus","box":"birthday","value":"1990-06-15","updated_at":"..."}`

`value` and `updated_at` are `null` when the box is empty. Needs `read`.
Works for inactive users.

### DELETE /v1/vault?user_id=<uuid>&box=<label>

→ `200 {"user_id":"<uuid>","realm":"silicon-circus","box":"birthday","deleted":true}`

`deleted: false` when there was nothing to delete. Needs `write`. Works
for inactive users, and on a box that no longer opens, because nothing is
decrypted.

| Error | Status |
|---|---|
| `bad_box` / `bad_user_id` / `bad_value` (empty, over 16 KiB, or not UTF-8) / `missing_params` / `bad_json` | 400 |
| `capability_denied`: no grant for this label, or a signing key not enrolled for the vault | 403 |
| `user_inactive` (PUT only) | 403 |
| `unknown_user` | 404 |
| `vault_integrity`: a stored box would not open (tampering, or a retired master key). Our fault, audited as an error. | 500 |
| `vault_unavailable`: this server has no vault key configured (every vault call, delete included) | 503 |

Any request body over 256 KiB, to any endpoint, is refused unread with
`413 {"error":"body_too_large"}`, before authentication.

## Removed

`POST /v1/award` and the `collectibles` field of `/v1/valuables` were
removed in v0.6.0, together with zero-value assets. Game inventory
(badges, doubloons, crackers) has no monetary value and belongs to the
game, not to Azooka Bay. A call to `/v1/award` now gets
`404 {"error":"not_found"}`.

## Not yet implemented

`POST /v1/exchange` — the cross-realm bridge (e.g. circus tokens ↔
Onboard credits). The ledger already supports it end to end; the endpoint
waits for the first consumer. See TODO.md.
