# Ed25519 signing and verification, bound directly to the system OpenSSL
# (libcrypto >= 1.1.1). No third-party shard: hand-rolled curve arithmetic
# has no place in the security core, and OpenSSL's implementation is
# constant-time, continuously audited, and already linked into every
# Crystal process that touches TLS.
#
# Validated against RFC 8032 test vectors in spec/ed25519_spec.cr.

require "openssl/lib_crypto"

# Only the raw-key and one-shot sign/verify functions are missing from
# Crystal's own LibCrypto binding; EVP_MD_CTX_new/free come from stdlib
# (redeclaring them would be a fun-redefinition error).
@[Link("crypto")]
lib LibEd25519
  alias Pkey = Void*

  # NID_ED25519 from openssl/obj_mac.h — stable public constant.
  NID_ED25519 = 1087

  fun pkey_new_raw_private = EVP_PKEY_new_raw_private_key(type : LibC::Int, e : Void*, key : UInt8*, keylen : LibC::SizeT) : Pkey
  fun pkey_new_raw_public = EVP_PKEY_new_raw_public_key(type : LibC::Int, e : Void*, key : UInt8*, keylen : LibC::SizeT) : Pkey
  fun pkey_get_raw_public = EVP_PKEY_get_raw_public_key(pkey : Pkey, pub : UInt8*, len : LibC::SizeT*) : LibC::Int
  fun pkey_free = EVP_PKEY_free(pkey : Pkey) : Void
  fun digest_sign_init = EVP_DigestSignInit(ctx : LibCrypto::EVP_MD_CTX, pctx : Void*, type : Void*, e : Void*, pkey : Pkey) : LibC::Int
  fun digest_sign = EVP_DigestSign(ctx : LibCrypto::EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
  fun digest_verify_init = EVP_DigestVerifyInit(ctx : LibCrypto::EVP_MD_CTX, pctx : Void*, type : Void*, e : Void*, pkey : Pkey) : LibC::Int
  fun digest_verify = EVP_DigestVerify(ctx : LibCrypto::EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
end

module AzookaBay
  module Ed25519
    SEED_SIZE       = 32
    PUBLIC_KEY_SIZE = 32
    SIGNATURE_SIZE  = 64

    class Error < Exception; end

    # Holds a private key. Lives on the SITE side: Azooka Bay itself never
    # stores or receives one — it verifies with public keys only.
    class SigningKey
      @pkey : LibEd25519::Pkey

      def self.generate : SigningKey
        new(Random::Secure.random_bytes(SEED_SIZE))
      end

      def initialize(seed : Bytes)
        raise Error.new("seed must be #{SEED_SIZE} bytes, got #{seed.size}") unless seed.size == SEED_SIZE
        @pkey = LibEd25519.pkey_new_raw_private(LibEd25519::NID_ED25519, Pointer(Void).null, seed, LibC::SizeT.new(seed.size))
        raise Error.new("EVP_PKEY_new_raw_private_key failed") if @pkey.null?
      end

      def public_key : Bytes
        buf = Bytes.new(PUBLIC_KEY_SIZE)
        len = LibC::SizeT.new(PUBLIC_KEY_SIZE)
        raise Error.new("EVP_PKEY_get_raw_public_key failed") if LibEd25519.pkey_get_raw_public(@pkey, buf, pointerof(len)) != 1
        buf
      end

      def sign(message : Bytes) : Bytes
        ctx = LibCrypto.evp_md_ctx_new
        raise Error.new("EVP_MD_CTX_new failed") if ctx.null?
        begin
          raise Error.new("EVP_DigestSignInit failed") if LibEd25519.digest_sign_init(ctx, Pointer(Void).null, Pointer(Void).null, Pointer(Void).null, @pkey) != 1
          sig = Bytes.new(SIGNATURE_SIZE)
          siglen = LibC::SizeT.new(SIGNATURE_SIZE)
          raise Error.new("EVP_DigestSign failed") if LibEd25519.digest_sign(ctx, sig, pointerof(siglen), message, LibC::SizeT.new(message.size)) != 1
          sig[0, siglen.to_i]
        ensure
          LibCrypto.evp_md_ctx_free(ctx)
        end
      end

      def finalize
        LibEd25519.pkey_free(@pkey) unless @pkey.null?
      end
    end

    # Holds a public key. This is all Azooka Bay ever stores per site key:
    # a database leak yields nothing capable of producing a valid request.
    class VerifyKey
      @pkey : LibEd25519::Pkey

      def initialize(public_key : Bytes)
        raise Error.new("public key must be #{PUBLIC_KEY_SIZE} bytes, got #{public_key.size}") unless public_key.size == PUBLIC_KEY_SIZE
        @pkey = LibEd25519.pkey_new_raw_public(LibEd25519::NID_ED25519, Pointer(Void).null, public_key, LibC::SizeT.new(public_key.size))
        raise Error.new("EVP_PKEY_new_raw_public_key failed") if @pkey.null?
      end

      # False on any invalid signature; raises only on internal OpenSSL
      # failure. Verification failure is a normal, expected outcome and
      # must never be an exception path.
      def verify?(message : Bytes, signature : Bytes) : Bool
        return false unless signature.size == SIGNATURE_SIZE
        ctx = LibCrypto.evp_md_ctx_new
        raise Error.new("EVP_MD_CTX_new failed") if ctx.null?
        begin
          raise Error.new("EVP_DigestVerifyInit failed") if LibEd25519.digest_verify_init(ctx, Pointer(Void).null, Pointer(Void).null, Pointer(Void).null, @pkey) != 1
          LibEd25519.digest_verify(ctx, signature, LibC::SizeT.new(signature.size), message, LibC::SizeT.new(message.size)) == 1
        ensure
          LibCrypto.evp_md_ctx_free(ctx)
        end
      end

      def finalize
        LibEd25519.pkey_free(@pkey) unless @pkey.null?
      end
    end
  end
end
