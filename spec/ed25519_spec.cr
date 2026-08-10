require "./spec_helper"

# Known-answer tests from RFC 8032 §7.1. If these pass, the OpenSSL binding
# is producing byte-exact standard Ed25519 — not merely something self-consistent.
private RFC8032_VECTORS = [
  {
    seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    msg:  "",
    sig:  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    msg:  "72",
    sig:  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    pub:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    msg:  "af82",
    sig:  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
]

describe AzookaBay::Ed25519 do
  it "reproduces the RFC 8032 test vectors byte-exactly" do
    RFC8032_VECTORS.each do |v|
      key = AzookaBay::Ed25519::SigningKey.new(v[:seed].hexbytes)
      key.public_key.should eq(v[:pub].hexbytes)
      key.sign(v[:msg].hexbytes).should eq(v[:sig].hexbytes)
    end
  end

  it "verifies RFC 8032 signatures with only the public key" do
    RFC8032_VECTORS.each do |v|
      verify = AzookaBay::Ed25519::VerifyKey.new(v[:pub].hexbytes)
      verify.verify?(v[:msg].hexbytes, v[:sig].hexbytes).should be_true
    end
  end

  it "round-trips a freshly generated keypair" do
    key = AzookaBay::Ed25519::SigningKey.generate
    msg = "spend:pirate-ship:tom:1:bones".to_slice
    sig = key.sign(msg)
    AzookaBay::Ed25519::VerifyKey.new(key.public_key).verify?(msg, sig).should be_true
  end

  it "rejects a tampered message" do
    key = AzookaBay::Ed25519::SigningKey.generate
    verify = AzookaBay::Ed25519::VerifyKey.new(key.public_key)
    sig = key.sign("amount=1".to_slice)
    verify.verify?("amount=9".to_slice, sig).should be_false
  end

  it "rejects a signature from a different key" do
    other = AzookaBay::Ed25519::SigningKey.generate
    verify = AzookaBay::Ed25519::VerifyKey.new(AzookaBay::Ed25519::SigningKey.generate.public_key)
    msg = "hello".to_slice
    verify.verify?(msg, other.sign(msg)).should be_false
  end

  it "rejects garbage and wrong-length signatures without raising" do
    verify = AzookaBay::Ed25519::VerifyKey.new(AzookaBay::Ed25519::SigningKey.generate.public_key)
    msg = "hello".to_slice
    verify.verify?(msg, Bytes.new(64, 0_u8)).should be_false
    verify.verify?(msg, Bytes.new(10, 0_u8)).should be_false
    verify.verify?(msg, Bytes.empty).should be_false
  end

  it "rejects malformed key material" do
    expect_raises(AzookaBay::Ed25519::Error) { AzookaBay::Ed25519::SigningKey.new(Bytes.new(16)) }
    expect_raises(AzookaBay::Ed25519::Error) { AzookaBay::Ed25519::VerifyKey.new(Bytes.new(31)) }
  end
end
