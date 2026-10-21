require "./spec_helper"

private def signed_request
  key = AzookaBay::Ed25519::SigningKey.generate
  args = {
    site_id:   "pirate-ship",
    key_id:    "ps-key-1",
    method:    "POST",
    path:      "/v1/spend?debug=0",
    body:      %({"user":"tom","asset":"bones","amount":1}).to_slice,
    timestamp: 1_753_400_000_i64,
    nonce:     AzookaBay::Signing.generate_nonce,
  }
  sig = AzookaBay::Signing.sign(key, **args)
  {AzookaBay::Ed25519::VerifyKey.new(key.public_key), sig, args}
end

describe AzookaBay::Signing do
  it "verifies a correctly signed request" do
    verify, sig, args = signed_request
    AzookaBay::Signing.verify?(verify, sig, **args).should be_true
  end

  it "rejects tampering with any signed field" do
    verify, sig, args = signed_request

    AzookaBay::Signing.verify?(verify, sig, **args.merge(site_id: "dog-house")).should be_false
    AzookaBay::Signing.verify?(verify, sig, **args.merge(key_id: "ps-key-2")).should be_false
    AzookaBay::Signing.verify?(verify, sig, **args.merge(method: "GET")).should be_false
    AzookaBay::Signing.verify?(verify, sig, **args.merge(path: "/v1/spend?debug=1")).should be_false
    AzookaBay::Signing.verify?(verify, sig, **args.merge(body: %({"user":"tom","asset":"bones","amount":9}).to_slice)).should be_false
    AzookaBay::Signing.verify?(verify, sig, **args.merge(timestamp: args[:timestamp] + 1)).should be_false
    AzookaBay::Signing.verify?(verify, sig, **args.merge(nonce: AzookaBay::Signing.generate_nonce)).should be_false
  end

  it "treats malformed signature encoding as failure, not exception" do
    verify, _sig, args = signed_request
    AzookaBay::Signing.verify?(verify, "!!not-base64!!", **args).should be_false
    AzookaBay::Signing.verify?(verify, "", **args).should be_false
    AzookaBay::Signing.verify?(verify, Base64.strict_encode(Bytes.new(10)), **args).should be_false
  end

  it "refuses fields that could smuggle canonical-string delimiters" do
    key = AzookaBay::Ed25519::SigningKey.generate
    expect_raises(AzookaBay::Signing::FieldError) do
      AzookaBay::Signing.canonical("evil\nsite", "k", "POST", "/x", Bytes.empty, 0_i64, "n0nce")
    end
    expect_raises(AzookaBay::Signing::FieldError) do
      AzookaBay::Signing.canonical("site", "k", "POST", "/x y", Bytes.empty, 0_i64, "n0nce")
    end
    expect_raises(AzookaBay::Signing::FieldError) do
      AzookaBay::Signing.canonical("site", "k", "post", "/x", Bytes.empty, 0_i64, "n0nce")
    end
    # and on the verify path the same inputs are a false, never a raise
    verify, sig, args = signed_request
    AzookaBay::Signing.verify?(verify, sig, **args.merge(site_id: "evil\nsite")).should be_false
  end

  it "binds the signature to the exact request even with an empty body" do
    key = AzookaBay::Ed25519::SigningKey.generate
    verify = AzookaBay::Ed25519::VerifyKey.new(key.public_key)
    ts = 1_753_400_000_i64
    sig = AzookaBay::Signing.sign(key, "s1", "k1", "GET", "/v1/balance", Bytes.empty, ts, "abc123")
    AzookaBay::Signing.verify?(verify, sig, "s1", "k1", "GET", "/v1/balance", Bytes.empty, ts, "abc123").should be_true
    AzookaBay::Signing.verify?(verify, sig, "s1", "k1", "GET", "/v1/balance", "x".to_slice, ts, "abc123").should be_false
  end

  it "accepts timestamps inside the skew window and rejects outside" do
    now = 1_753_400_000_i64
    skew = AzookaBay::Signing::MAX_CLOCK_SKEW.to_i64
    AzookaBay::Signing.fresh?(now, now).should be_true
    AzookaBay::Signing.fresh?(now - skew, now).should be_true
    AzookaBay::Signing.fresh?(now + skew, now).should be_true
    AzookaBay::Signing.fresh?(now - skew - 1, now).should be_false
    AzookaBay::Signing.fresh?(now + skew + 1, now).should be_false
    AzookaBay::Signing.fresh?(Int64::MIN, now).should be_false # no overflow
    AzookaBay::Signing.fresh?(Int64::MAX, now).should be_false
  end

  it "generates unique, token-safe nonces" do
    nonces = Array.new(1000) { AzookaBay::Signing.generate_nonce }
    nonces.uniq.size.should eq(1000)
    nonces.each { |n| n.should match(AzookaBay::Signing::TOKEN_PATTERN) }
  end
end
