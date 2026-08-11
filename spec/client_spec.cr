require "./spec_helper"
require "http/server"
require "socket"

# The client is exercised against a real HTTP server that VERIFIES the signature
# with this shard's own verifier — the same check the Azooka Bay server makes.
# That is the property worth testing: not "the client sent some headers", but
# "what the client signs is what the far end can verify", which is the whole
# reason a site depends on this shard instead of reimplementing the canonical
# string.
private class FakeBay
  getter last_path : String? = nil
  getter last_body : String? = nil
  getter last_method : String? = nil
  getter verified : Bool = false
  getter port : Int32 = 0
  getter nonces = [] of String

  def initialize(@key : AzookaBay::Ed25519::VerifyKey, &@handler : String -> {Int32, String})
    @server = HTTP::Server.new do |ctx|
      body = ctx.request.body.try(&.gets_to_end) || ""
      @last_method = ctx.request.method
      @last_path = ctx.request.resource
      @last_body = body

      @nonces << (ctx.request.headers[AzookaBay::Signing::HEADER_NONCE]? || "")
      @verified = AzookaBay::Signing.verify?(
        @key,
        ctx.request.headers[AzookaBay::Signing::HEADER_SIGNATURE]? || "",
        ctx.request.headers[AzookaBay::Signing::HEADER_SITE]? || "",
        ctx.request.headers[AzookaBay::Signing::HEADER_KEY]? || "",
        ctx.request.method,
        ctx.request.resource,
        body.to_slice,
        (ctx.request.headers[AzookaBay::Signing::HEADER_TIMESTAMP]? || "0").to_i64,
        ctx.request.headers[AzookaBay::Signing::HEADER_NONCE]? || "x",
      )

      status, payload = @handler.call(ctx.request.resource)
      ctx.response.status_code = status
      ctx.response.content_type = "application/json"
      ctx.response.print payload
    end
    @port = @server.bind_unused_port.port
    spawn { @server.listen }
    Fiber.yield
  end

  def close
    @server.close
  end
end

private SEED = "1".rjust(64, '0')

private def with_bay(&block : AzookaBay::Client, FakeBay -> Nil)
  key = AzookaBay::Ed25519::SigningKey.new(SEED.hexbytes)
  bay = FakeBay.new(AzookaBay::Ed25519::VerifyKey.new(key.public_key)) do |path|
    case path
    when "/v1/whoami"       then {200, %({"site":"pirate-ship","key":"ps-1"})}
    when "/v1/login/start"  then {202, %({"ok":true})}
    when "/v1/login/verify" then {200, %({"user_id":"u-1","email":"tom@example.com","redirect_path":"/midway"})}
    when "/v1/issue"        then {200, %({"transaction_id":42,"balance":20,"replay":false})}
    when "/v1/spend"        then {200, %({"transaction_id":43,"balance":19,"replay":false})}
    when .starts_with?("/v1/valuables") then {200, %({"user_id":"u-1","realm":"silicon-circus","balances":{"bones":25},"collectibles":[]})}
    when "/v1/nope"         then {401, %({"error":"unauthorized"})}
    when "/v1/refused"      then {502, %({"error":"email_failed"})}
    when "/v1/garbage"      then {500, "<html>gateway</html>"}
    else                         {404, %({"error":"not_found"})}
    end
  end
  client = AzookaBay::Client.new("pirate-ship", "ps-1", SEED, "http://127.0.0.1:#{bay.port}")
  begin
    block.call(client, bay)
  ensure
    bay.close
  end
end

describe AzookaBay::Client do
  it "signs requests the server's own verifier accepts" do
    with_bay do |client, bay|
      client.whoami["site"].should eq "pirate-ship"
      bay.verified.should be_true
    end
  end

  it "signs the body it actually sends" do
    with_bay do |client, bay|
      client.login_start("tom@example.com", redirect_path: "/midway")
      bay.verified.should be_true
      JSON.parse(bay.last_body.not_nil!)["email"].should eq "tom@example.com"
    end
  end

  it "signs the path INCLUDING its query string" do
    with_bay do |client, bay|
      client.valuables("u-1")
      bay.verified.should be_true                       # would fail if only the path were signed
      bay.last_path.not_nil!.should contain "user_id=u-1"
    end
  end

  it "accepts a seed as hex, base64, or raw bytes" do
    raw = SEED.hexbytes
    expected = AzookaBay::Ed25519::SigningKey.new(raw).public_key.hexstring
    AzookaBay::Client.new("s", "k", SEED).public_key_hex.should eq expected
    AzookaBay::Client.new("s", "k", Base64.strict_encode(raw)).public_key_hex.should eq expected
    AzookaBay::Client.new("s", "k", raw).public_key_hex.should eq expected
  end

  it "rejects a seed it cannot decode rather than signing with nonsense" do
    expect_raises(AzookaBay::Client::ConfigError) { AzookaBay::Client.new("s", "k", "not-a-key") }
    # valid base64, wrong length: must be the SAME helpful error, not a crypto error
    expect_raises(AzookaBay::Client::ConfigError) do
      AzookaBay::Client.new("s", "k", Base64.strict_encode(Bytes.new(16)))
    end
  end

  it "normalizes a trailing slash off base_url so the signed path matches the sent path" do
    with_bay do |client, bay|
      slashed = AzookaBay::Client.new("pirate-ship", "ps-1", SEED,
        "http://127.0.0.1:#{bay.port}/")
      slashed.whoami["site"].should eq "pirate-ship"
      bay.verified.should be_true
      bay.last_path.should eq "/v1/whoami"
    end
  end

  it "preserves the opaque 401 instead of interpreting it" do
    with_bay do |client, _|
      ex = expect_raises(AzookaBay::Client::Error) { client.get("/v1/nope") }
      ex.status.should eq 401
      ex.code.should eq "unauthorized"
      ex.unauthorized?.should be_true
    end
  end

  it "marks a refused send retryable, and an auth failure not" do
    with_bay do |client, _|
      (expect_raises(AzookaBay::Client::Error) { client.get("/v1/refused") }).retryable?.should be_true
      (expect_raises(AzookaBay::Client::Error) { client.get("/v1/nope") }).retryable?.should be_false
    end
  end

  it "reports a non-JSON response as such rather than raising a parse error" do
    with_bay do |client, _|
      ex = expect_raises(AzookaBay::Client::Error) { client.get("/v1/garbage") }
      ex.code.should eq "bad_response"
      ex.status.should eq 500
    end
  end

  it "returns typed results" do
    with_bay do |client, _|
      login = client.login_verify("tok")
      login.user_id.should eq "u-1"
      login.redirect_path.should eq "/midway"

      client.issue(user_id: "u-1", asset: "bones", amount: 20_i64,
                   idempotency_key: "k1").balance.should eq 20
      client.spend(user_id: "u-1", asset: "bones", amount: 1_i64,
                   idempotency_key: "k2").transaction_id.should eq 43
      client.valuables("u-1").balances["bones"].should eq 25
    end
  end

  it "makes exactly ONE request per call — a timeout is never a silent nonce replay" do
    # Crystal's stock HTTP::Client retries once on IO::Error with the SAME
    # request (same nonce, same signature) — a replay the server rejects
    # with an opaque 401, possibly after real work was done. This test
    # counts attempts against a black hole: accept, never answer. It goes
    # red if a stdlib change resurrects the hidden retry.
    attempts = Atomic(Int32).new(0)
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.port
    spawn do
      loop do
        sock = server.accept? || break
        attempts.add(1)
        spawn do
          sock.gets_to_end rescue nil # swallow the request, answer nothing
        end
      end
    end

    client = AzookaBay::Client.new("pirate-ship", "ps-1", SEED,
      "http://127.0.0.1:#{port}", read_timeout: 250.milliseconds)
    ex = expect_raises(AzookaBay::Client::TransportError) { client.whoami }
    ex.timeout?.should be_true

    sleep 400.milliseconds # would-be retry window
    attempts.get.should eq 1
    server.close
  end

  it "sends a fresh nonce every call" do
    with_bay do |client, bay|
      3.times { client.whoami }
      # nonces are single-use server-side, so a client that reused one would have
      # its second request rejected as a replay
      bay.nonces.size.should eq 3
      bay.nonces.uniq.size.should eq 3
      bay.nonces.none?(&.empty?).should be_true
    end
  end
end
