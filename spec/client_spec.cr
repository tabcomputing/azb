require "./spec_helper"
require "http/server"
require "socket"
require "file_utils"
require "../src/azb/login_file"

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
    when .starts_with?("/v1/user")
      {200, %({"user_id":"u-1","realm":"silicon-circus","active":false,"hold":{"message":"Paused."},"member_since":"2026-10-01T12:00:00Z"})}
    when "/v1/issue"        then {200, %({"transaction_id":42,"balance":20,"replay":false})}
    when "/v1/issue-capped" then {409, %({"error":"issue_limit_site"})}
    when .starts_with?("/v1/issue/allowance?")
      if path.includes?("user_id=")
        {200, %({"asset":"scc","site":{"limit":1000,"issued":60,"remaining":940},"account":{"limit":20,"issued":10,"remaining":10}})}
      else
        {200, %({"asset":"scc","site":{"limit":1000,"issued":60,"remaining":940},"account":null})}
      end
    when "/v1/spend"        then {200, %({"transaction_id":43,"balance":19,"replay":false})}
    when .starts_with?("/v1/balance") then {200, %({"user_id":"u-1","realm":"silicon-circus","balances":{"bones":25,"emeralds":50}})}
    when .starts_with?("/v1/valuables")
      if path.includes?("held")
        {200, %({"user_id":"u-1","realm":"silicon-circus","balances":{"bones":25},"collectibles":[],"hold":{"message":"Account needs attention.","url":"https://x/billing"}})}
      else
        {200, %({"user_id":"u-1","realm":"silicon-circus","balances":{"bones":25},"collectibles":[],"hold":null})}
      end
    when "/v1/site/login"   then {200, %({"changed":true})}
    when "/v1/skus"         then {200, %({"realm":"silicon-circus","publishable_key":"pk_test_x","skus":[{"id":"coins-20","name":"20 Coins","asset":"scc","quantity":20,"cents":500}]})}
    when "/v1/checkout"     then {200, %({"payment_id":7,"session_id":"cs_test_1","client_secret":"cs_test_1_secret","url":null,"publishable_key":"pk_test_x","expires_at":"2026-10-21T18:00:00Z","replay":false})}
    when .starts_with?("/v1/checkout?session_id=")
      {200, %({"session_id":"cs_test_1","user_id":"u-1","status":"settled","sku":"coins-20","asset":"scc","quantity":20,"amount_cents":500,"currency":"usd","transaction_id":88,"balance":20,"settled_at":"2026-10-21T17:04:51Z"})}
    when .starts_with?("/v1/payments?")
      {200, %({"payments":[{"seq":7,"payment_id":12,"session_id":"cs_test_1","user_id":"u-1","status":"refunded","sku":"coins-20","asset":"scc","quantity":20,"amount_cents":500,"currency":"usd","transaction_id":88,"at":"2026-11-14T09:12:40Z"},{"seq":8,"payment_id":13,"session_id":null,"user_id":"u-1","status":"failed","sku":"coins-20","asset":"scc","quantity":20,"amount_cents":500,"currency":"usd","transaction_id":null,"at":"2026-11-14T09:13:00Z"}],"next":8,"more":true})}
    when "/v1/stripe-down"  then {502, %({"error":"stripe_unreachable","message":"no answer"})}
    when "/v1/bad-settings" then {400, %({"error":"invalid_login_settings","message":"digits codes must be 6-10 long"})}
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

  it "reads hot-path balances without flows" do
    with_bay do |client, _|
      b = client.balances("u-1")
      b["bones"].should eq 25
      b["emeralds"].should eq 50
    end
  end

  it "surfaces the account hold from valuables, active as held? false" do
    with_bay do |client, _|
      active = client.valuables("u-1")
      active.held?.should be_false            # explicit null collapses to nil
      active.hold.should be_nil

      held = client.valuables("held-user")
      held.held?.should be_true
      held.hold.not_nil!["message"].should eq "Account needs attention."
      held.hold.not_nil!["url"].should eq "https://x/billing"
    end
  end

  it "treats a hold-less response (older server) as active" do
    key = AzookaBay::Ed25519::SigningKey.new(SEED.hexbytes)
    bay = FakeBay.new(AzookaBay::Ed25519::VerifyKey.new(key.public_key)) do |_|
      {200, %({"user_id":"u-1","realm":"r","balances":{},"collectibles":[]})} # no hold key at all
    end
    client = AzookaBay::Client.new("s", "k", SEED, "http://127.0.0.1:#{bay.port}")
    client.valuables("u-1").held?.should be_false
    bay.close
  end

  it "reports a non-JSON response as such rather than raising a parse error" do
    with_bay do |client, _|
      ex = expect_raises(AzookaBay::Client::Error) { client.get("/v1/garbage") }
      ex.code.should eq "bad_response"
      ex.status.should eq 500
    end
  end

  it "sets the site's login look as one signed PUT, sending only what was given" do
    with_bay do |client, bay|
      client.set_login("code", code_style: "vocab", code_length: 4, vocab: %w(ka zo mi),
        label: "Magic Word", email_body: "Words: {code}").should be_true
      bay.verified.should be_true
      bay.last_method.should eq "PUT"
      bay.last_path.should eq "/v1/site/login"
      sent = JSON.parse(bay.last_body.not_nil!).as_h
      sent.keys.sort.should eq %w(code_length code_style email_body label method vocab)
      sent["vocab"].as_a.map(&.as_s).should eq %w(ka zo mi)
      sent["code_length"].as_i.should eq 4
    end
  end

  it "pushes a login file as the same PUT" do
    with_bay do |client, bay|
      dir = File.tempname("azb-login")
      Dir.mkdir(dir)
      begin
        File.write(File.join(dir, "words.txt"), "ka\nzo\nmi\n")
        File.write(File.join(dir, "body.txt"), "Words: {code}")
        File.write(File.join(dir, "login.yml"), <<-YAML)
          method: code
          code: { style: vocab, length: 4, vocab_file: words.txt }
          label: Magic Word
          email: { body_file: body.txt }
          YAML
        client.set_login_file(File.join(dir, "login.yml")).should be_true
      ensure
        FileUtils.rm_rf(dir)
      end
      bay.verified.should be_true
      bay.last_path.should eq "/v1/site/login"
      sent = JSON.parse(bay.last_body.not_nil!).as_h
      sent.keys.sort.should eq %w(code_length code_style email_body label method vocab)
      sent["vocab"].as_a.map(&.as_s).should eq %w(ka zo mi)
      sent["email_body"].as_s.should eq "Words: {code}"
    end
  end

  it "carries the server's reason on errors that have one" do
    with_bay do |client, _|
      ex = expect_raises(AzookaBay::Client::Error) { client.put("/v1/bad-settings", {"method" => "code"}) }
      ex.code.should eq "invalid_login_settings"
      ex.message.not_nil!.should contain "digits codes must be 6-10 long"
    end
  end

  it "reads what the site may still issue, and knows a capped issue" do
    with_bay do |client, bay|
      left = client.issue_allowance("scc", "u-1")
      bay.last_path.should eq "/v1/issue/allowance?asset=scc&user_id=u-1"
      bay.verified.should be_true
      left.site.should eq AzookaBay::Client::Allowance.new(1000, 60, 940)
      left.account.try(&.remaining).should eq 10
      client.issue_allowance("scc").account.should be_nil
      ex = expect_raises(AzookaBay::Client::Error) { client.post("/v1/issue-capped", {} of String => String) }
      {ex.status, ex.issue_limit?, ex.retryable?}.should eq({409, true, false})
    end
  end

  it "returns typed results" do
    with_bay do |client, bay|
      login = client.login_verify("tok")
      login.user_id.should eq "u-1"
      login.redirect_path.should eq "/midway"

      client.login_verify_code("tom@example.com", "Ali Ka Thul").user_id.should eq "u-1"
      standing = client.user("u-1")
      standing.active.should be_false
      standing.hold.not_nil!["message"].should eq "Paused."
      standing.member_since.should eq "2026-10-01T12:00:00Z"

      client.issue(user_id: "u-1", asset: "bones", amount: 20_i64,
                   idempotency_key: "k1").balance.should eq 20
      client.spend(user_id: "u-1", asset: "bones", amount: 1_i64,
                   idempotency_key: "k2").transaction_id.should eq 43
      JSON.parse(bay.last_body.not_nil!).as_h.has_key?("sku").should be_false
      client.spend(user_id: "u-1", asset: "bones", amount: 1_i64,
                   idempotency_key: "k3", sku: "skee-ball")
      JSON.parse(bay.last_body.not_nil!)["sku"].should eq "skee-ball"
      client.valuables("u-1").balances["bones"].should eq 25
    end
  end

  it "sells through Azooka Bay: SKUs, a checkout, and how it went" do
    with_bay do |client, bay|
      catalog = client.skus
      catalog.publishable_key.should eq "pk_test_x"
      catalog.skus.first.cents.should eq 500
      opened = client.checkout("u-1", "coins-20", "buy-1", ui: "embedded")
      bay.verified.should be_true
      JSON.parse(bay.last_body.not_nil!).should eq JSON.parse(%({"user_id":"u-1","sku":"coins-20","ui":"embedded","idempotency_key":"buy-1"}))
      opened.client_secret.should eq "cs_test_1_secret"
      opened.url.should be_nil
      status = client.checkout_status("cs_test_1")
      bay.last_path.should eq "/v1/checkout?session_id=cs_test_1"
      status.settled?.should be_true
      status.user_id.should eq "u-1"
      status.balance.should eq 20
      status.settled_at.should eq "2026-10-21T17:04:51Z"
      # the payments feed, from where the site left off
      feed = client.payments(after: 6_i64)
      bay.last_path.should eq "/v1/payments?after=6&limit=100"
      bay.verified.should be_true
      feed.next.should eq 8
      feed.more.should be_true
      feed.changes.map(&.status).should eq ["refunded", "failed"]
      feed.changes[0].transaction_id.should eq 88
      feed.changes[0].at.should eq "2026-11-14T09:12:40Z"
      feed.changes[1].session_id.should be_nil
      feed.changes[1].transaction_id.should be_nil
      client.payments.next.should eq 8
      bay.last_path.should eq "/v1/payments?after=0&limit=100"
      # finishing in the page: asked for only when it isn't the default
      client.checkout("u-1", "coins-20", "buy-2", ui: "embedded", redirect: "if_required")
      JSON.parse(bay.last_body.not_nil!)["redirect"].should eq "if_required"
      ex = expect_raises(AzookaBay::Client::Error) { client.post("/v1/stripe-down", {"x" => 1}) }
      ex.retryable?.should be_true
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

# A site that logs people in at its login service: the login service and
# its branch, each checking the signature under its own key for the site.
private LOGIN_SEED = "2".rjust(64, '0')

private def with_login_service(enter_delay : Time::Span = Time::Span.zero, entered_as : String = "u-1",
                               login_stats : Int32 = 200, &block : AzookaBay::Client, FakeBay, FakeBay -> Nil)
  branch_key = AzookaBay::Ed25519::SigningKey.new(SEED.hexbytes)
  login_key = AzookaBay::Ed25519::SigningKey.new(LOGIN_SEED.hexbytes)
  entries = 0
  stats = ->(counts : String) { %({"site":"pirate-ship","as_of":"2026-11-03T12:00:00Z","windows":{"24h":{#{counts}},"7d":{#{counts}}}}) }
  service = FakeBay.new(AzookaBay::Ed25519::VerifyKey.new(login_key.public_key)) do |path|
    case path
    when "/v1/whoami"
      {200, %({"site":"pirate-ship","key":"ps-login-1","service":"login","version":"0.13.0","identity":{"branch":"games","key":"ls-1","version":"0.13.0"}})}
    when "/v1/login/start"  then {202, %({"ok":true})}
    when "/v1/login/verify" then {200, %({"user_id":"u-1","email":"tom@example.com","redirect_path":"/midway","pass":"AZBP2.fields.idsig.loginsig"})}
    when "/v1/site/login"   then {200, %({"changed":true})}
    when "/v1/stats"
      login_stats == 200 ? {200, stats.call(%("login_emails_sent":3,"login_emails_failed":1,"login_links_rejected":0))} : {login_stats, %({"error":"stats_unavailable"})}
    else                         {404, %({"error":"not_found"})}
    end
  end
  branch = FakeBay.new(AzookaBay::Ed25519::VerifyKey.new(branch_key.public_key)) do |path|
    case path
    when "/v1/members/enter"
      entries += 1
      sleep enter_delay if entries == 1
      {200, %({"user_id":"#{entered_as}","email":"tom@example.com","replay":#{entries > 1}})}
    when .starts_with?("/v1/user")
      {200, %({"user_id":"u-1","realm":"silicon-circus","active":true,"hold":null,"member_since":"2026-10-01T12:00:00Z"})}
    when "/v1/stats"
      {200, stats.call(%("users_logged_in":5,"new_users":2,"login_emails_sent":1,"login_emails_failed":0,"login_links_rejected":0,"users_transacting":4))}
    else {404, %({"error":"not_found"})}
    end
  end
  client = AzookaBay::Client.new("pirate-ship", "ps-1", SEED, "http://127.0.0.1:#{branch.port}",
    read_timeout: 300.milliseconds).with_login("ps-login-1", LOGIN_SEED, "http://127.0.0.1:#{service.port}")
  begin
    block.call(client, service, branch)
  ensure
    service.close
    branch.close
  end
end

describe "AzookaBay::Client with a login service" do
  it "logs in at the login service and hands the pass to the branch; everything else is the branch's" do
    with_login_service do |client, service, branch|
      client.login?.should be_true
      client.login_start("tom@example.com", redirect_path: "/midway")
      service.last_path.should eq "/v1/login/start"
      service.verified.should be_true
      branch.last_path.should be_nil

      login = client.login_verify("tok")
      {login.user_id, login.email, login.redirect_path}.should eq({"u-1", "tom@example.com", "/midway"})
      JSON.parse(service.last_body.not_nil!)["token"].should eq "tok"
      branch.last_path.should eq "/v1/members/enter"
      branch.verified.should be_true
      JSON.parse(branch.last_body.not_nil!)["pass"].should eq "AZBP2.fields.idsig.loginsig"

      client.login_verify_code("tom@example.com", "123456").user_id.should eq "u-1"
      JSON.parse(service.last_body.not_nil!)["code"].should eq "123456"

      client.set_login("code", code_style: "digits", code_length: 6).should be_true
      service.last_path.should eq "/v1/site/login"
      me = client.login_whoami
      {me["service"], me["identity"]["branch"]}.should eq({"login", "games"})

      client.user("u-1").active.should be_true
      branch.last_path.should eq "/v1/user?user_id=u-1"
    end
  end

  it "retries handing over the pass once, freshly signed, after a timeout" do
    with_login_service(enter_delay: 600.milliseconds) do |client, _, branch|
      client.login_verify("tok").user_id.should eq "u-1"
      enters = branch.nonces.size
      enters.should eq 2
      branch.nonces.uniq.size.should eq 2
    end
  end

  it "refuses a login the branch answers with another user" do
    with_login_service(entered_as: "u-2") do |client, _, _|
      ex = expect_raises(AzookaBay::Client::Error) { client.login_verify("tok") }
      ex.code.should eq "branch_mismatch"
      ex = expect_raises(AzookaBay::Client::Error) { client.login_verify_code("tom@example.com", "123456") }
      ex.code.should eq "branch_mismatch"
    end
  end

  it "adds the login service's login mail to the branch's stats" do
    with_login_service do |client, _, _|
      day = client.stats["windows"]["24h"]
      day["login_emails_sent"].should eq 4
      day["login_emails_failed"].should eq 1
      day["users_logged_in"].should eq 5
      client.stats["windows"]["7d"]["login_emails_sent"].should eq 4
    end
  end

  it "gives the branch's numbers alone, marked partial, when the login service can't answer" do
    with_login_service(login_stats: 503) do |client, _, _|
      s = client.stats
      s["partial"].as_bool.should be_true
      s["windows"]["24h"]["login_emails_sent"].as_i64.should eq 1
    end
  end

  it "reads the login service's settings with the site's, all three or none, and refuses v0.12's identity ones" do
    vars = {"AZB_SITE_ID" => "pirate-ship", "AZB_KEY_ID" => "ps-1", "AZB_PRIVATE_KEY_SEED" => SEED}
    login = {"AZB_LOGIN_KEY_ID" => "ps-login-1", "AZB_LOGIN_KEY_SEED" => LOGIN_SEED, "AZB_LOGIN_URL" => "https://login.example.test"}
    begin
      vars.each { |k, v| ENV[k] = v }
      AzookaBay::Client.from_env.login?.should be_false
      ENV["AZB_LOGIN_KEY_ID"] = "ps-login-1"
      ENV["AZB_LOGIN_KEY_SEED"] = LOGIN_SEED
      expect_raises(AzookaBay::Client::ConfigError, /go together/) { AzookaBay::Client.from_env }
      ENV["AZB_LOGIN_URL"] = "http://login.example.test"
      expect_raises(AzookaBay::Client::ConfigError, /AZB_LOGIN_URL must be https/) { AzookaBay::Client.from_env }
      ENV["AZB_LOGIN_URL"] = "https://login.example.test"
      AzookaBay::Client.from_env.login?.should be_true
      # in the clear only to this machine: a service beside the site
      bare = AzookaBay::Client.new("pirate-ship", "ps-1", SEED)
      {"http://10.0.0.5:17306", "http://login.example.test", "ftp://login.example.test", "login.example.test"}.each do |url|
        expect_raises(AzookaBay::Client::ConfigError, /AZB_LOGIN_URL must be https/) { bare.with_login("ps-login-1", LOGIN_SEED, url) }
      end
      {"http://127.0.0.1:17306", "http://localhost:17306", "http://[::1]:17306", "https://login.example.test/"}.each do |url|
        bare.with_login("ps-login-1", LOGIN_SEED, url).login?.should be_true
      end
      ENV["AZB_IDENTITY_KEY_ID"] = "ps-id-1"
      expect_raises(AzookaBay::Client::ConfigError, /AZB_IDENTITY_KEY_ID is gone since azb 0.8/) { AzookaBay::Client.from_env }
      expect_raises(AzookaBay::Client::ConfigError, /no login service/) do
        AzookaBay::Client.new("s", "k", SEED).login_whoami
      end
    ensure
      (vars.keys + login.keys + ["AZB_IDENTITY_KEY_ID"]).each { |k| ENV.delete(k) }
    end
  end
end
