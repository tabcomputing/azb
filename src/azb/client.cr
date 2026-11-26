require "http/client"
require "json"
require "base64"
require "uri"
require "./signing"

module AzookaBay
  # :nodoc:
  #
  # HTTP::Client with the stdlib's silent one-retry REMOVED. Crystal's
  # `exec` rescues IO::Error (including read timeouts) and re-sends the
  # SAME request — same nonce, same signature. For an AZB1 client that
  # retry can never help (we open a fresh connection per call, so there is
  # no stale keep-alive to recover from) and actively harms: the re-send
  # is a nonce replay, answered with an opaque 401, and for login/start it
  # can follow an email that was actually sent. One call = one request,
  # guaranteed; the caller decides about retries, with a fresh signature.
  #
  # Overrides the non-block exec path using stdlib-private helpers —
  # deliberately version-coupled; the attempt-counting spec goes red if a
  # stdlib change alters this behavior.
  class OneShotHTTPClient < HTTP::Client
    def exec(request : HTTP::Request) : HTTP::Client::Response
      around_exec(request) do
        implicit_compression = implicit_compression?(request)
        set_defaults request
        run_before_request_callbacks(request)
        response = exec_internal_single(request, implicit_compression: implicit_compression)
        raise IO::EOFError.new("Unexpected end of http response") unless response
        handle_response(response)
      end
    end
  end

  # A signed client for the Azooka Bay API.
  #
  # Every call except `health?` is AZB1-signed with this site's Ed25519 key. The
  # canonical string comes from `AzookaBay::Signing` — the same module the
  # server's verifier uses — so a client's signature is byte-identical to what
  # the far end rebuilds, by construction rather than by agreement.
  #
  # The private seed never leaves the process: it is loaded once into a signing
  # key and is never logged, echoed, or sent.
  #
  #     azb = AzookaBay::Client.from_env
  #     azb.login_start("tom@example.com", redirect_path: "/midway")
  #     login = azb.login_verify(token)
  #     azb.issue(user_id: login.user_id, asset: "bones", amount: 20,
  #               idempotency_key: "welcome-#{login.user_id}")
  #
  # A site that logs its people in at its own login service (the split,
  # server v0.13.0+) gives the client the service's address and its key
  # there too (`with_login`, or AZB_LOGIN_* in `from_env`). Logins then go
  # to the login service and everything else to the site's branch, as
  # before; the calls and what they return are the same.
  class Client
    # An API error, post-authentication or otherwise.
    #
    # `code` is the server's own error string. Authentication failures are a
    # single opaque `401 unauthorized` BY DESIGN — the server records the real
    # reason (missing header, stale timestamp, unknown key, bad signature,
    # replay) in its audit log only, because distinguishing them in the response
    # would hand an attacker an oracle. This client preserves that: it does not
    # guess at, embellish, or "helpfully" reinterpret a 401.
    class Error < Exception
      getter status : Int32
      getter code : String

      def initialize(@status, @code, message : String? = nil)
        super(message || "azooka bay: #{code} (#{status})")
      end

      def unauthorized? : Bool
        @status == 401 && @code == "unauthorized"
      end

      # Retryable by the caller: the mail provider refused, Stripe never
      # answered (retry a checkout under the SAME idempotency key), or the
      # login service couldn't reach identity (the link or code is still
      # good), and the server's own guidance for the code is "retry later".
      def retryable? : Bool
        @code.in?("email_failed", "stripe_unreachable", "identity_unavailable")
      end

      # An issue refused by the site's issue limits (server v0.13.0+):
      # `issue_limit_account` (this member has had their share for now) or
      # `issue_limit_site` (the site has given all it may today: tell the
      # operator). Refused and capped: decline, don't retry until the
      # window has moved. The idempotency key is left unused.
      def issue_limit? : Bool
        @code.in?("issue_limit_account", "issue_limit_site")
      end
    end

    class ConfigError < Exception; end

    # The request never completed: nothing was signed away and no response
    # exists. `timeout?` distinguishes a read timeout (the request MAY have
    # reached the server and been processed — the response was simply not
    # seen) from a connection failure (it almost certainly did not).
    #
    # Retrying is the CALLER's choice, and this client guarantees a retry
    # is a fresh request (new nonce, new timestamp, new signature) — never
    # a byte replay. Retrying mutating calls is safe when you reuse the
    # same idempotency_key: a processed-but-unseen first attempt replays
    # its original result. login_start has no idempotency key; a retry may
    # send a second email and spends a second rate-limit slot.
    class TransportError < Exception
      getter timeout : Bool

      def initialize(cause : Exception, @timeout : Bool)
        super("azooka bay transport: #{cause.message}", cause: cause)
      end

      def timeout? : Bool
        @timeout
      end
    end

    getter site_id : String
    getter key_id : String
    getter base_url : String

    # The connection to the site's login service, when it logs people in there.
    @login : Client? = nil

    # `seed` is the 32-byte Ed25519 private seed, as raw bytes, 64 hex chars, or
    # base64. Accepting all three matters in practice: a credential file's
    # encoding is decided by whatever wrote it, and a silent format mismatch
    # would surface as an unexplainable 401 rather than a clear error here.
    # Timeouts are deliberate: this client sits on venue hot paths (the arcade
    # spend), where a hung connection must fail fast rather than hang a
    # visitor's request. Tune per site if needed. One call is ONE request
    # (see OneShotHTTPClient), so read_timeout bounds the whole call.
    #
    # `base_url` is the site's branch, and there is no default (since 0.11):
    # with more than one branch, a default would quietly pick one of them.
    # It must be https://host[:port], or http:// to this machine; anything
    # else raises ConfigError here rather than failing later.
    def initialize(@site_id : String, @key_id : String, seed : String | Bytes,
                   base_url : String,
                   @connect_timeout : Time::Span = 5.seconds,
                   @read_timeout : Time::Span = 10.seconds)
      # A trailing slash would make the SENT resource "//v1/..." while
      # "/v1/..." was signed — an undebuggable opaque 401. Normalize it away.
      @base_url = Client.branch_url(base_url).chomp("/")
      @key = Ed25519::SigningKey.new(seed.is_a?(Bytes) ? seed : decode_seed(seed))
    end

    # Reads AZB_SITE_ID, AZB_KEY_ID, AZB_PRIVATE_KEY_SEED and AZB_BASE_URL,
    # all four required — the names the enrollment tooling emits. AZB_BASE_URL
    # is the site's branch; unset, this raises (since 0.11: there is no
    # default, so a site can't quietly call a branch that isn't its own). With
    # AZB_LOGIN_KEY_ID, AZB_LOGIN_KEY_SEED and AZB_LOGIN_URL (all three),
    # logins go to the site's login service (`with_login`).
    def self.from_env : Client
      site = ENV["AZB_SITE_ID"]? || raise ConfigError.new("AZB_SITE_ID not set")
      key  = ENV["AZB_KEY_ID"]? || raise ConfigError.new("AZB_KEY_ID not set")
      seed = ENV["AZB_PRIVATE_KEY_SEED"]? || raise ConfigError.new("AZB_PRIVATE_KEY_SEED not set")
      if old = %w(AZB_IDENTITY_KEY_ID AZB_IDENTITY_KEY_SEED AZB_IDENTITY_URL).find { |k| ENV[k]?.presence }
        # Said rather than ignored: a site still set up for v0.12 would
        # otherwise log people in at its branch without a word.
        raise ConfigError.new("#{old} is gone since azb 0.8: a site logs its people in at its own login " \
                              "service (AZB_LOGIN_KEY_ID, AZB_LOGIN_KEY_SEED, AZB_LOGIN_URL)")
      end
      base = ENV["AZB_BASE_URL"]?.presence ||
             raise ConfigError.new("AZB_BASE_URL not set: the address of this site's branch " \
                                   "(http://127.0.0.1:17304 when it runs beside the site); there is no default")
      client = new(site, key, seed, base)
      login = {ENV["AZB_LOGIN_KEY_ID"]?.presence, ENV["AZB_LOGIN_KEY_SEED"]?.presence, ENV["AZB_LOGIN_URL"]?.presence}
      if login.any?
        login_key, login_seed, login_url = login
        unless login_key && login_seed && login_url
          raise ConfigError.new("AZB_LOGIN_KEY_ID, AZB_LOGIN_KEY_SEED and AZB_LOGIN_URL go together")
        end
        client.with_login(login_key, login_seed, login_url)
      end
      client
    end

    # Log this site's people in at its own login service (server v0.13.0+):
    # the site's key there (a second one, beside the branch's, from
    # `azookabay-login-enroll site`; the site id is the same) and the
    # service's address. login_start, login_verify, login_verify_code and
    # set_login go to the login service; a login's pass is handed to the
    # branch, which makes or refreshes the member there. Everything else
    # goes to the branch, as before. Returns self.
    # The login service's address must be https, or plain http to this
    # machine (a service beside the site, on loopback): its answers carry
    # people's passes, which the branch takes as who they are, so one swapped
    # on the wire would log someone in as another. Raises ConfigError.
    def with_login(key_id : String, seed : String | Bytes, url : String) : self
      @login = Client.new(@site_id, key_id, seed, Client.login_url(url), @connect_timeout, @read_timeout)
      self
    end

    # The hosts that are this machine: the only ones plain http may reach.
    LOOPBACK = {"127.0.0.1", "localhost", "[::1]", "::1"}

    # url, checked as new wants it: https://host[:port], or http:// to this
    # machine (a branch beside the site, on loopback), nothing else. Since
    # 0.11, as for a login service: a branch's answers are balances, holds
    # and who a pass is, and a site trusts them. A path, query or fragment
    # would be dropped without a word (a call goes to the host and port, at
    # its own path), so they're refused.
    def self.branch_url(url : String) : String
      url = url.strip
      uri = URI.parse(url) rescue nil
      host = uri.try(&.host)
      ok = uri && host && !host.empty? &&
           (uri.scheme == "https" || (uri.scheme == "http" && LOOPBACK.includes?(host))) &&
           uri.path.in?("", "/") && uri.query.nil? && uri.fragment.nil?
      raise ConfigError.new("an Azooka Bay address must be https://host[:port], or http:// to this machine " \
                            "(AZB_BASE_URL, AZB_LOGIN_URL): got #{url.inspect}") unless ok
      url
    end

    # url, checked as with_login wants it.
    def self.login_url(url : String) : String
      url = url.strip
      uri = URI.parse(url)
      host = uri.host
      ok = host && !host.empty? &&
           (uri.scheme == "https" ||
            (uri.scheme == "http" && LOOPBACK.includes?(host)))
      raise ConfigError.new("AZB_LOGIN_URL must be https://host[:port] (or http:// to 127.0.0.1): it carries people's logins") unless ok
      url
    end

    # Whether logins go to the site's login service.
    def login? : Bool
      !@login.nil?
    end

    # True when the four settings from_env requires are present: the three
    # credentials and the branch's address (required since 0.11). Lets a
    # service report its own readiness (a /health that says what is wired,
    # not merely that it is up) instead of discovering a missing setting at
    # a visitor's first login. It doesn't check them: from_env does.
    def self.configured? : Bool
      !!(ENV["AZB_SITE_ID"]?.presence && ENV["AZB_KEY_ID"]?.presence &&
         ENV["AZB_PRIVATE_KEY_SEED"]?.presence && ENV["AZB_BASE_URL"]?.presence)
    end

    # The public half of this site's signing key, hex — useful for confirming a
    # deployment holds the key the server actually enrolled.
    def public_key_hex : String
      @key.public_key.hexstring
    end

    # ── Transport ─────────────────────────────────────────────────────────────

    # `path` is signed exactly as sent, INCLUDING the query string, so build it
    # once and pass the same string here.
    def call(method : String, path : String, body : String? = nil) : JSON::Any
      bytes = (body || "").to_slice
      ts    = Time.utc.to_unix
      nonce = Signing.generate_nonce

      headers = HTTP::Headers{
        Signing::HEADER_SITE      => @site_id,
        Signing::HEADER_KEY       => @key_id,
        Signing::HEADER_TIMESTAMP => ts.to_s,
        Signing::HEADER_NONCE     => nonce,
        Signing::HEADER_SIGNATURE => Signing.sign(@key, @site_id, @key_id, method, path, bytes, ts, nonce),
      }
      headers["Content-Type"] = "application/json" if body

      uri = URI.parse(@base_url)
      http = OneShotHTTPClient.new(uri)
      http.connect_timeout = @connect_timeout
      http.read_timeout = @read_timeout
      res = begin
        http.exec(method, path, headers: headers, body: body)
      rescue ex : IO::TimeoutError
        raise TransportError.new(ex, timeout: true)
      rescue ex : IO::Error
        raise TransportError.new(ex, timeout: false)
      ensure
        http.close
      end
      parsed = begin
        JSON.parse(res.body.presence || "{}")
      rescue JSON::ParseException
        raise Error.new(res.status_code, "bad_response", "azooka bay returned non-JSON (#{res.status_code})")
      end
      unless res.success?
        code = parsed["error"]?.try(&.as_s?) || "unknown"
        # A few errors carry the server's reason (e.g. invalid_login_settings
        # says what's wrong); authentication failures never do.
        reason = parsed["message"]?.try(&.as_s?)
        raise Error.new(res.status_code, code, reason ? "azooka bay: #{code} (#{res.status_code}): #{reason}" : nil)
      end
      parsed
    end

    def get(path : String) : JSON::Any
      call("GET", path)
    end

    def post(path : String, payload) : JSON::Any
      call("POST", path, payload.to_json)
    end

    def put(path : String, payload) : JSON::Any
      call("PUT", path, payload.to_json)
    end

    # ── Endpoints (docs/api.md) ───────────────────────────────────────────────

    # passes and pass_errors: a login handed on (`passes_for`, server
    # v0.17.0+), by site: a pass for each other site, to carry to it, or
    # why none was made. Empty otherwise.
    record Login, user_id : String, email : String, redirect_path : String?,
      passes : Hash(String, String) = {} of String => String,
      pass_errors : Hash(String, String) = {} of String => String
    record Transaction, transaction_id : Int64, balance : Int64, replay : Bool
    record Reversal, transaction_id : Int64, reversed_id : Int64, replay : Bool
    record Award, award_id : Int64, collectible : String, copy_no : Int32, replay : Bool
    # A member's standing in the calling site's realm (server v0.6.0+,
    # GET /v1/user). `hold` is opaque JSON (render message/url verbatim,
    # and when either is null, say it in your own words: a hold from
    # identity carries none; a site learns WHETHER, never WHY), nil when
    # active.
    record Standing, user_id : String, realm : String, active : Bool,
      hold : JSON::Any?, member_since : String?
    # `hold` is the account-inactive signal (server v0.4.1+): nil when the
    # user is active (also nil against older servers that never send it, and
    # nil is normalized from an explicit JSON null too), otherwise an opaque
    # {message?, url?}. Kept as raw JSON::Any on purpose — the client does
    # not model or interpret it, preserving the property that a site learns
    # WHETHER a user is held, never WHY. Render message/url verbatim; and if
    # you poll this to re-validate a session, fail OPEN when unreachable.
    record Valuables, user_id : String, realm : String,
      balances : Hash(String, Int64), collectibles : Array(JSON::Any),
      hold : JSON::Any? = nil do
      def held? : Bool
        !hold.nil?
      end
    end

    # Selling through Azooka Bay (server v0.9.0+). A SKU is a bundle of one
    # of the realm's assets at a price, from the realm's file; `cents` is
    # what the buyer pays.
    record Sku, id : String, name : String, asset : String, quantity : Int64, cents : Int64
    record Catalog, realm : String, publishable_key : String, skus : Array(Sku)
    # An open Stripe Checkout session: mount Stripe's embedded Checkout with
    # `publishable_key` and `client_secret`, or send the buyer to `url`
    # (hosted). Opening one credits nothing; Stripe's word does.
    record Checkout, payment_id : Int64, session_id : String, client_secret : String?,
      url : String?, publishable_key : String, expires_at : String?, replay : Bool
    # status: open, processing (a bank debit clearing: the coins come when
    # it does), settled, expired, failed, mismatched (paid, not what was
    # offered: nothing credited), refunded, charged_back or reinstated (a
    # dispute won and its coins restored; server v0.11.0+). `balance` is the
    # buyer's balance of the asset once settled or reinstated. `user_id` is the buyer:
    # show a purchase only to them (a session id in a URL can be anyone's).
    # `settled_at` (RFC 3339; server v0.9.1+) is when Azooka Bay recorded
    # the payment, kept after a refund; nil if it never settled.
    record CheckoutStatus, session_id : String, user_id : String, status : String, sku : String,
      asset : String, quantity : Int64, amount_cents : Int64, currency : String,
      transaction_id : Int64?, balance : Int64?, settled_at : String? = nil do
      def settled? : Bool
        status == "settled"
      end

      def open? : Bool
        status == "open"
      end
    end
    # One entry of the payments feed (server v0.11.0+): what a payment
    # became (`status`, as for CheckoutStatus) and when (`at`, RFC 3339),
    # with the payment's own facts. `session_id` is nil for a checkout
    # Stripe refused to open, `transaction_id` (the purchase) until it
    # settled.
    record PaymentChange, seq : Int64, payment_id : Int64, session_id : String?, user_id : String,
      status : String, sku : String, asset : String, quantity : Int64, amount_cents : Int64,
      currency : String, transaction_id : Int64?, at : String
    # A page of the feed. Keep `next` and ask after it next time; `more`:
    # there may be more now, so ask again at once.
    record PaymentChanges, changes : Array(PaymentChange), next : Int64, more : Bool
    # One of the site's issue limits on an asset (server v0.13.0+), with
    # what it has issued in the window and what's left.
    record Allowance, limit : Int64, issued : Int64, remaining : Int64
    # `site`: the 24-hour limit; `account`: the member's 30-day one (nil
    # when no user was named). nil: no such limit.
    record IssueAllowance, asset : String, site : Allowance?, account : Allowance?

    # Unsigned liveness probe — the one call needing no credentials.
    def health? : Bool
      HTTP::Client.get("#{@base_url}/health").success?
    rescue
      false
    end

    # Signed no-op proving the whole authentication path: credentials, clock
    # skew, canonical string, key still active. Worth calling before blaming
    # anything else.
    def whoami : JSON::Any
      get("/v1/whoami")
    end

    # The same at the site's login service (server v0.13.0+): this site,
    # its key there, and what identity says of the service (`identity`:
    # the site's branch, the service's key and version; null when identity
    # doesn't answer). A deploy checks that `login_whoami["identity"]["branch"]`
    # is the branch's own `whoami["branch"]`.
    def login_whoami : JSON::Any
      login_client.get("/v1/whoami")
    end

    # Email the user a way in, branded as this site: a magic link, a typed
    # code (the "Magic Word", server v0.7.0+), or both — whichever the
    # site's login method is (set by the Azooka Bay operator).
    #
    # Always 202, whether the address has an account, is new, or is silently
    # rate-limited — the server refuses to be an account-existence oracle. A
    # caller must not undo that by reporting the outcome differently.
    def login_start(email : String, redirect_path : String? = nil, request_ip : String? = nil) : Nil
      payload = {"email" => email}
      payload["redirect_path"] = redirect_path if redirect_path
      payload["request_ip"] = request_ip if request_ip
      logins.post("/v1/login/start", payload)
    end

    # Redeem the token from the emailed link. The first successful verify CREATES
    # the user; afterwards Azooka Bay plays no part in the session — that is the
    # calling site's to own.
    #
    # passes_for (server v0.17.0+, at a login service only): other sites of
    # the realm to hand this login on to, so the person needn't log in at
    # each (docs/api.md, "A login handed on"). Each site's pass comes back
    # in `passes`, for this site to carry to it; a site that doesn't take
    # this site's logins is in `pass_errors` (handoff_refused), and the
    # login itself goes ahead. At most 16; an empty list asks for none. A
    # site the service said nothing of (one older than v0.17.0) is in
    # `pass_errors` as "unanswered". Without a login service it raises
    # ConfigError: a branch's own login makes no passes.
    def login_verify(token : String, passes_for : Array(String)? = nil) : Login
      verify({"token" => token}, passes_for)
    end

    # Redeem a typed login code (server v0.7.0+): the code from the email,
    # as the user typed it (case, spaces and hyphens don't matter), with the
    # address it was sent to. Every failure is the same 401 invalid_code —
    # wrong, used, expired, too many tries — so show one message for all.
    # passes_for: as for login_verify.
    def login_verify_code(email : String, code : String, passes_for : Array(String)? = nil) : Login
      verify({"email" => email, "code" => code}, passes_for)
    end

    # A login handed on (server v0.17.0+): another site of this realm
    # logged the person in and asked for a pass for this site
    # (`passes_for`, there), and the pass has been brought here: from that
    # site's page to this site's, then to this site's server. Hand it over
    # here, and the branch checks it, makes or refreshes the member, and
    # checks their standing, as at a login of this site's own
    # (user_inactive). Then open this site's own session for the user.
    #
    # The branch takes a pass from another site's login only where this
    # site's realm file says it takes that site's logins, and a pass handed
    # on enters ONCE: brought again, even by this site, it's refused
    # (invalid_pass). So this call isn't retried: on a TransportError, the
    # person logs in again at the other site. Who it is, is the pass's
    # word, read here to check the branch's answer (branch_mismatch), never
    # trusted for more: only the branch checks its signatures. A pass for
    # another site, or one that isn't a pass at all, is refused here
    # (invalid_pass) without asking the branch.
    def enter(pass : String) : Login
      named = Client.pass_fields(pass)
      unless named && named[2] == @site_id
        raise Error.new(403, "invalid_pass", "azooka bay: invalid_pass: #{named ? "a pass for another site" : "not a pass"}")
      end
      user_id, email, _ = named
      entered = post("/v1/members/enter", {"pass" => pass})
      unless entered["user_id"]?.try(&.as_s?) == user_id
        raise Error.new(502, "branch_mismatch", "the branch answered a pass for #{user_id} with another user; refused")
      end
      Login.new(user_id, entered["email"]?.try(&.as_s?) || email, nil)
    end

    # The user id, email and site a pass names (AZBP2: its fields, read
    # without checking a signature), or nil if it isn't one.
    def self.pass_fields(pass : String) : {String, String, String}?
      return nil unless pass.bytesize <= 2048
      parts = pass.split('.')
      return nil unless parts.size == 4 && parts[0] == "AZBP2" && parts[1].matches?(/\A[A-Za-z0-9_-]+\z/)
      fields = String.new(Base64.decode(parts[1]))
      return nil unless fields.valid_encoding?
      f = fields.split('\n')
      return nil unless f.size == 10 && !f[3].empty? && !f[4].empty? && !f[5].empty?
      {f[3], f[4], f[5]}
    rescue Base64::Error
      nil
    end

    # At a login service, a login answers with a pass for this site's
    # branch (signed by identity and by the service), and the branch,
    # handed it, makes or refreshes the member and checks their standing in
    # the realm (user_inactive, as before). A timeout handing it over is
    # retried once, freshly signed: the branch answers the same pass from
    # the same site as it did the first time.
    #
    # Who logged in is identity's word, not the branch's: the branch must
    # answer with the user the pass names, or the login is refused
    # (branch_mismatch), so a branch, honest or not, can never hand the
    # site another person's account.
    private def verify(fields : Hash(String, String), passes_for : Array(String)?) : Login
      passes_for = nil if passes_for.try(&.empty?)
      service = @login
      unless service
        if passes_for
          raise ConfigError.new("passes_for needs a login service (with_login, or AZB_LOGIN_* in from_env): " \
                                "a branch's own login makes no passes")
        end
        return login(post("/v1/login/verify", fields))
      end
      payload = {} of String => String | Array(String)
      fields.each { |k, v| payload[k] = v }
      payload["passes_for"] = passes_for if passes_for
      r = service.post("/v1/login/verify", payload)
      pass = r["pass"]?.try(&.as_s?)
      user_id = r["user_id"]?.try(&.as_s?)
      email = r["email"]?.try(&.as_s?)
      unless pass && user_id && email
        raise Error.new(502, "bad_response", "azooka bay's login service answered a login without a pass, user id or email")
      end
      entered = begin
        post("/v1/members/enter", {"pass" => pass})
      rescue ex : TransportError
        post("/v1/members/enter", {"pass" => pass})
      end
      unless entered["user_id"]?.try(&.as_s?) == user_id
        raise Error.new(502, "branch_mismatch", "the branch answered a pass for #{user_id} with another user; refused")
      end
      passes, pass_errors = strings(r["passes"]?), strings(r["pass_errors"]?)
      passes_for.try &.each { |site| pass_errors[site] = "unanswered" unless passes[site]? || pass_errors[site]? }
      Login.new(user_id, email, r["redirect_path"]?.try(&.as_s?), passes, pass_errors)
    end

    private def strings(any : JSON::Any?) : Hash(String, String)
      h = {} of String => String
      any.try(&.as_h?).try &.each { |k, v| v.as_s?.try { |sv| h[k] = sv } }
      h
    end

    private def login(r : JSON::Any) : Login
      Login.new(r["user_id"].as_s, r["email"].as_s, r["redirect_path"]?.try(&.as_s?))
    end

    # Set this site's own login presentation (server v0.8.0+): the method
    # ("link", "code" or "both"), the code's look (`code_style` "digits"
    # with `code_length` 6-10, or "vocab": `code_length` entries from
    # `vocab` joined by `separator`), what the email calls it (`label`), and
    # the email copy (templates with {site} {label} {code} {link} {minutes};
    # the fallback email is the link sent after too many wrong codes).
    #
    # Whole-set: anything omitted returns to its default. Idempotent, so a
    # site can call it on every deploy; returns whether anything changed.
    # The server validates it all (strength floor, prefix-free vocabulary,
    # templates) and refuses with 400 invalid_login_settings and the reason.
    # The landing URL and From address are the operator's: not settable here.
    # email_image and its alt text (server v0.14.0+): a small image at the
    # head of the login emails, a path on the site's own address.
    def set_login(method : String, *, code_style : String? = nil, code_length : Int32? = nil,
                  vocab : Array(String)? = nil, separator : String? = nil, label : String? = nil,
                  email_subject : String? = nil, email_body : String? = nil,
                  fallback_subject : String? = nil, fallback_body : String? = nil,
                  email_image : String? = nil, email_image_alt : String? = nil) : Bool
      payload = {"method" => JSON::Any.new(method)}
      payload["code_style"] = JSON::Any.new(code_style) if code_style
      payload["code_length"] = JSON::Any.new(code_length.to_i64) if code_length
      payload["vocab"] = JSON::Any.new(vocab.map { |v| JSON::Any.new(v) }) if vocab
      payload["separator"] = JSON::Any.new(separator) if separator
      payload["label"] = JSON::Any.new(label) if label
      payload["email_subject"] = JSON::Any.new(email_subject) if email_subject
      payload["email_body"] = JSON::Any.new(email_body) if email_body
      payload["fallback_subject"] = JSON::Any.new(fallback_subject) if fallback_subject
      payload["fallback_body"] = JSON::Any.new(fallback_body) if fallback_body
      payload["email_image"] = JSON::Any.new(email_image) if email_image
      payload["email_image_alt"] = JSON::Any.new(email_image_alt) if email_image_alt
      logins.put("/v1/site/login", payload)["changed"].as_bool
    end

    # A member's standing in this site's realm (server v0.6.0+): cheap to
    # poll for re-validating a session. A non-member is an unknown user (404).
    # Fail OPEN when Azooka Bay is unreachable.
    def user(user_id : String) : Standing
      r = get("/v1/user?user_id=#{URI.encode_www_form(user_id)}")
      hold = r["hold"]?.try { |h| h.raw.nil? ? nil : h }
      Standing.new(r["user_id"].as_s, r["realm"].as_s, r["active"].as_bool, hold,
        r["member_since"]?.try(&.as_s?))
    end

    # Mint asset to a user. `kind` is "grant" (winnings, promos, comps) or
    # "purchase" (issued for payment; reconciles against Stripe). A realm
    # that sells through Azooka Bay (`checkout`) refuses "purchase" here:
    # there only Stripe's word makes one. The site's issue limits (server
    # v0.13.0+) refuse it past them: `Error#issue_limit?`.
    def issue(user_id : String, asset : String, amount : Int64, idempotency_key : String,
              kind : String = "grant", description : String? = nil,
              metadata : Hash(String, JSON::Any)? = nil) : Transaction
      payload = {"user_id" => JSON::Any.new(user_id), "asset" => JSON::Any.new(asset),
                 "amount" => JSON::Any.new(amount), "idempotency_key" => JSON::Any.new(idempotency_key),
                 "kind" => JSON::Any.new(kind)}
      payload["description"] = JSON::Any.new(description) if description
      payload["metadata"] = JSON::Any.new(metadata) if metadata
      tx(post("/v1/issue", payload))
    end

    # What the site may still issue of an asset before its issue limits
    # refuse it (server v0.13.0+): `site`, its 24-hour limit, and, for
    # `user_id`, `account`, the member's 30-day one; nil where there's no
    # such limit. A hint for saying no before asking: two issues can race
    # between this and `issue`, which is still the check.
    def issue_allowance(asset : String, user_id : String? = nil) : IssueAllowance
      path = "/v1/issue/allowance?asset=#{URI.encode_www_form(asset)}"
      path += "&user_id=#{URI.encode_www_form(user_id)}" if user_id
      r = get(path)
      allowance = ->(a : JSON::Any?) do
        a.try { |x| x.raw.nil? ? nil : Allowance.new(x["limit"].as_i64, x["issued"].as_i64, x["remaining"].as_i64) }
      end
      IssueAllowance.new(r["asset"].as_s, allowance.call(r["site"]?), allowance.call(r["account"]?))
    end

    # sku: what the spend bought, an id written as a SKU's is (a-z, 0-9,
    # '-' or '_'), kept on the transaction (server v0.11.0+; an older server
    # ignores it). Part of what a retry under the same key must match.
    def spend(user_id : String, asset : String, amount : Int64, idempotency_key : String,
              description : String? = nil, sku : String? = nil) : Transaction
      payload = {"user_id" => JSON::Any.new(user_id), "asset" => JSON::Any.new(asset),
                 "amount" => JSON::Any.new(amount), "idempotency_key" => JSON::Any.new(idempotency_key)}
      payload["sku"] = JSON::Any.new(sku) if sku
      payload["description"] = JSON::Any.new(description) if description
      tx(post("/v1/spend", payload))
    end

    # Compensating transaction: posts the exact negation of the original. A site
    # may reverse only transactions it created.
    def reverse(transaction_id : Int64, idempotency_key : String, reason : String? = nil) : Reversal
      payload = {"transaction_id" => transaction_id, "idempotency_key" => idempotency_key}
      payload = payload.merge({"reason" => reason}) if reason
      r = post("/v1/reverse", payload)
      Reversal.new(r["transaction_id"].as_i64, r["reversed_id"].as_i64, r["replay"]?.try(&.as_bool?) || false)
    end

    # Removed from the server in v0.6.0 (game inventory belongs to the game,
    # not Azooka Bay): against v0.6.0+ this raises Client::Error (404).
    @[Deprecated("Azooka Bay v0.6.0 removed /v1/award: keep inventory in your own service")]
    def award(user_id : String, collectible : String, idempotency_key : String,
              copy_no : Int32? = nil, metadata : Hash(String, JSON::Any)? = nil) : Award
      payload = {"user_id" => JSON::Any.new(user_id), "collectible" => JSON::Any.new(collectible),
                 "idempotency_key" => JSON::Any.new(idempotency_key)}
      payload["copy_no"] = JSON::Any.new(copy_no.to_i64) if copy_no
      payload["metadata"] = JSON::Any.new(metadata) if metadata
      r = post("/v1/award", payload)
      Award.new(r["award_id"].as_i64, r["collectible"].as_s, r["copy_no"].as_i.to_i32,
                r["replay"]?.try(&.as_bool?) || false)
    end

    # Just the balances, through this site's realm wall — the hot-path
    # display read (arcade cabinet wallet). No flows/collectibles/hold, so
    # it stays flat regardless of ledger history. For the coin drop itself
    # use `spend` (attempting is the check, and its response carries the new
    # balance); this is only for painting a number on a screen.
    def balances(user_id : String) : Hash(String, Int64)
      r = get("/v1/balance?user_id=#{URI.encode_www_form(user_id)}")
      out = {} of String => Int64
      r["balances"].as_h.each { |k, v| out[k] = v.as_i64 }
      out
    end

    # Everything the user owns, through this site's realm wall.
    def valuables(user_id : String) : Valuables
      r = get("/v1/valuables?user_id=#{URI.encode_www_form(user_id)}")
      balances = {} of String => Int64
      r["balances"].as_h.each { |k, v| balances[k] = v.as_i64 }
      # Collapse both absent and explicit-null to nil, so `held?` is a clean
      # active/inactive test regardless of server version.
      hold = r["hold"]?.try { |h| h.raw.nil? ? nil : h }
      Valuables.new(r["user_id"].as_s, r["realm"].as_s, balances,
                    r["collectibles"]?.try(&.as_a) || [] of JSON::Any, hold)
    end

    # Realm-scoped shared metadata — what every venue in the realm agrees on
    # about a user. Not for app-private data, and not for valuables.
    def profile(user_id : String) : JSON::Any
      get("/v1/profile?user_id=#{URI.encode_www_form(user_id)}")
    end

    # Merge-patch: each key is set to its value; an explicit null deletes it.
    def put_profile(user_id : String, entries : Hash(String, JSON::Any)) : JSON::Any
      put("/v1/profile", {"user_id" => user_id, "entries" => entries})
    end

    # The realm's SKUs this site may sell, cheapest first (server v0.9.0+).
    def skus : Catalog
      r = get("/v1/skus")
      list = r["skus"].as_a.map do |k|
        Sku.new(k["id"].as_s, k["name"].as_s, k["asset"].as_s, k["quantity"].as_i64, k["cents"].as_i64)
      end
      Catalog.new(r["realm"].as_s, r["publishable_key"].as_s, list)
    end

    # Opens a Stripe Checkout session for one SKU (server v0.9.0+). `ui` is
    # "hosted" (send the buyer to `url`) or "embedded" (mount it in your page
    # with `client_secret`). The idempotency key names the checkout: a retry
    # under it returns the same session; a new purchase needs a new key.
    #
    # `redirect` (embedded only, server v0.9.1+): "always" sends the buyer
    # to the realm's return page once paid; "if_required" only after a
    # payment method that left the page, so a page can carry on in Stripe.js's
    # `onComplete` and ask `checkout_status` itself. (An older server ignores
    # it and always redirects.)
    def checkout(user_id : String, sku : String, idempotency_key : String,
                 ui : String = "hosted", redirect : String = "always") : Checkout
      payload = {"user_id" => user_id, "sku" => sku, "ui" => ui, "idempotency_key" => idempotency_key}
      payload["redirect"] = redirect unless redirect == "always"
      r = post("/v1/checkout", payload)
      Checkout.new(r["payment_id"].as_i64, r["session_id"].as_s, r["client_secret"]?.try(&.as_s?),
        r["url"]?.try(&.as_s?), r["publishable_key"].as_s, r["expires_at"]?.try(&.as_s?),
        r["replay"]?.try(&.as_bool?) || false)
    end

    # How a checkout went (server v0.9.0+). The return page asks once, not
    # on a timer: Stripe sends the buyer back only when the checkout is
    # finished, and asking has Azooka Bay check with Stripe if its webhook
    # hasn't arrived yet, crediting the payment then. Still `open?`: say
    # it's being confirmed and offer to check again. A site that gave
    # something beyond coins asks again at the member's login, to hear of
    # a refund or chargeback.
    def checkout_status(session_id : String) : CheckoutStatus
      r = get("/v1/checkout?session_id=#{URI.encode_www_form(session_id)}")
      CheckoutStatus.new(r["session_id"].as_s, r["user_id"].as_s, r["status"].as_s, r["sku"].as_s, r["asset"].as_s,
        r["quantity"].as_i64, r["amount_cents"].as_i64, r["currency"].as_s,
        r["transaction_id"]?.try(&.as_i64?), r["balance"]?.try(&.as_i64?), r["settled_at"]?.try(&.as_s?))
    end

    # The payments feed (server v0.11.0+): this site's payment changes
    # after `after`, in order, each once, none skipped. A site that gave
    # something beyond coins for a payment reads it once a day from the
    # last `next` it kept (and asks `checkout_status` at the member's
    # login), so nothing goes unheard past a day; otherwise it's a
    # catch-up read (starting your own record of sales, after an outage).
    # Never more often than daily. While `more`, ask again after `next`
    # for the rest. `limit`: 1 to 500.
    def payments(after : Int64 = 0_i64, limit : Int32 = 100) : PaymentChanges
      r = get("/v1/payments?after=#{after}&limit=#{limit}")
      list = r["payments"].as_a.map do |e|
        PaymentChange.new(e["seq"].as_i64, e["payment_id"].as_i64, e["session_id"]?.try(&.as_s?),
          e["user_id"].as_s, e["status"].as_s, e["sku"].as_s, e["asset"].as_s, e["quantity"].as_i64,
          e["amount_cents"].as_i64, e["currency"].as_s, e["transaction_id"]?.try(&.as_i64?), e["at"].as_s)
      end
      PaymentChanges.new(list, r["next"].as_i64, r["more"]?.try(&.as_bool?) || false)
    end

    # This site's numbers (GET /v1/stats): people logged in, new and
    # transacting, and login mail sent, failed and links rejected, per
    # window (15m, 24h, 7d, 30d). With a login service, its mail counts are
    # added in, since logins happen there; the people stay the branch's,
    # which sees each one come in. If the login service can't answer, the
    # branch's numbers come back alone, marked `"partial": true`.
    def stats : JSON::Any
      r = get("/v1/stats")
      if service = @login
        theirs = begin
          service.get("/v1/stats")["windows"].as_h
        rescue Error | TransportError
          r.as_h["partial"] = JSON::Any.new(true)
          return r
        end
        windows = r["windows"].as_h
        theirs.each do |window, counts|
          next unless mine = windows[window]?.try(&.as_h?)
          counts.as_h.each do |metric, n|
            mine[metric] = JSON::Any.new((mine[metric]?.try(&.as_i64?) || 0_i64) + n.as_i64)
          end
        end
      end
      r
    end

    # Where logins go: the site's login service, when it has one.
    private def logins : Client
      @login || self
    end

    private def login_client : Client
      @login || raise ConfigError.new("no login service connection (with_login, or AZB_LOGIN_* in from_env)")
    end

    private def tx(r : JSON::Any) : Transaction
      Transaction.new(r["transaction_id"].as_i64, r["balance"].as_i64,
                      r["replay"]?.try(&.as_bool?) || false)
    end

    private def decode_seed(raw : String) : Bytes
      s = raw.strip
      decoded = s.matches?(/\A[0-9a-fA-F]{64}\z/) ? s.hexbytes : Base64.decode(s)
      # Length-check here so wrong-length base64 gets THIS error, not a raw
      # crypto error from key construction.
      raise ArgumentError.new("wrong length") unless decoded.size == Ed25519::SEED_SIZE
      decoded
    rescue
      raise ConfigError.new("private key seed must be 32 raw bytes, 64 hex chars, or base64")
    end
  end
end
