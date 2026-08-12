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
  class Client
    DEFAULT_BASE_URL = "https://api.azookabay.com"

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

      # Retryable by the caller: the mail provider refused, and the server's own
      # guidance for this code is "retry later".
      def retryable? : Bool
        @code == "email_failed"
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

    # `seed` is the 32-byte Ed25519 private seed, as raw bytes, 64 hex chars, or
    # base64. Accepting all three matters in practice: a credential file's
    # encoding is decided by whatever wrote it, and a silent format mismatch
    # would surface as an unexplainable 401 rather than a clear error here.
    # Timeouts are deliberate: this client sits on venue hot paths (the arcade
    # spend), where a hung connection must fail fast rather than hang a
    # visitor's request. Tune per site if needed. One call is ONE request
    # (see OneShotHTTPClient), so read_timeout bounds the whole call.
    def initialize(@site_id : String, @key_id : String, seed : String | Bytes,
                   base_url : String = DEFAULT_BASE_URL,
                   @connect_timeout : Time::Span = 5.seconds,
                   @read_timeout : Time::Span = 10.seconds)
      # A trailing slash would make the SENT resource "//v1/..." while
      # "/v1/..." was signed — an undebuggable opaque 401. Normalize it away.
      @base_url = base_url.chomp("/")
      @key = Ed25519::SigningKey.new(seed.is_a?(Bytes) ? seed : decode_seed(seed))
    end

    # Reads AZB_SITE_ID, AZB_KEY_ID, AZB_PRIVATE_KEY_SEED and optional
    # AZB_BASE_URL — the names the enrollment tooling emits.
    def self.from_env : Client
      site = ENV["AZB_SITE_ID"]? || raise ConfigError.new("AZB_SITE_ID not set")
      key  = ENV["AZB_KEY_ID"]? || raise ConfigError.new("AZB_KEY_ID not set")
      seed = ENV["AZB_PRIVATE_KEY_SEED"]? || raise ConfigError.new("AZB_PRIVATE_KEY_SEED not set")
      new(site, key, seed, ENV["AZB_BASE_URL"]? || DEFAULT_BASE_URL)
    end

    # True when all three credentials are present. Lets a service report its own
    # readiness (a /health that says what is wired, not merely that it is up)
    # instead of discovering a missing credential at a visitor's first login.
    def self.configured? : Bool
      !!(ENV["AZB_SITE_ID"]? && ENV["AZB_KEY_ID"]? && ENV["AZB_PRIVATE_KEY_SEED"]?)
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
      raise Error.new(res.status_code, parsed["error"]?.try(&.as_s?) || "unknown") unless res.success?
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

    record Login, user_id : String, email : String, redirect_path : String?
    record Transaction, transaction_id : Int64, balance : Int64, replay : Bool
    record Reversal, transaction_id : Int64, reversed_id : Int64, replay : Bool
    record Award, award_id : Int64, collectible : String, copy_no : Int32, replay : Bool
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

    # Mint a magic-link token and email it, branded as this site.
    #
    # Always 202, whether the address has an account, is new, or is silently
    # rate-limited — the server refuses to be an account-existence oracle. A
    # caller must not undo that by reporting the outcome differently.
    def login_start(email : String, redirect_path : String? = nil, request_ip : String? = nil) : Nil
      payload = {"email" => email}
      payload["redirect_path"] = redirect_path if redirect_path
      payload["request_ip"] = request_ip if request_ip
      post("/v1/login/start", payload)
    end

    # Redeem the token from the emailed link. The first successful verify CREATES
    # the user; afterwards Azooka Bay plays no part in the session — that is the
    # calling site's to own.
    def login_verify(token : String) : Login
      r = post("/v1/login/verify", {"token" => token})
      Login.new(r["user_id"].as_s, r["email"].as_s, r["redirect_path"]?.try(&.as_s?))
    end

    # Mint asset to a user. `kind` is "grant" (winnings, promos, comps) or
    # "purchase" (issued for payment; reconciles against Stripe).
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

    def spend(user_id : String, asset : String, amount : Int64, idempotency_key : String,
              description : String? = nil) : Transaction
      payload = {"user_id" => user_id, "asset" => asset, "amount" => amount,
                 "idempotency_key" => idempotency_key}
      payload = payload.merge({"description" => description}) if description
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
