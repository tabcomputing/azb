require "digest/sha256"
require "base64"
require "./ed25519"

module AzookaBay
  # Request signing protocol, version AZB1.
  #
  # Every request from a site to Azooka Bay carries five headers:
  #
  #   X-AZB-Site       site id ('pirate-ship')
  #   X-AZB-Key        key id (which of the site's registered keys signed)
  #   X-AZB-Timestamp  unix seconds, decimal
  #   X-AZB-Nonce      single-use random token (client: Random::Secure)
  #   X-AZB-Signature  base64 Ed25519 signature over the canonical string
  #
  # The canonical string binds the signature to every meaningful part of
  # the request — tamper with any of them and verification fails:
  #
  #   AZB1 \n site_id \n key_id \n METHOD \n path \n sha256(body) \n timestamp \n nonce
  #
  # Newline is the field separator, so no field may contain one. Fields are
  # validated against a conservative token alphabet and canonical() raises
  # on violation — ambiguity is an attack surface, not an edge case.
  #
  # The body is bound by SHA-256 digest, so arbitrary bytes are fine there.
  # The path is signed as-sent, INCLUDING the query string if present.
  #
  # This module is pure: no clock reads, no database. Replay defence is
  # completed by the server middleware (timestamp skew window + nonce
  # single-use, backed by the request_nonces table).
  module Signing
    VERSION_TAG = "AZB1"

    HEADER_SITE      = "X-AZB-Site"
    HEADER_KEY       = "X-AZB-Key"
    HEADER_TIMESTAMP = "X-AZB-Timestamp"
    HEADER_NONCE     = "X-AZB-Nonce"
    HEADER_SIGNATURE = "X-AZB-Signature"

    # Accepted clock skew between site and Azooka Bay, either direction.
    # Nonces must be remembered for at least this long (the reaper's floor).
    MAX_CLOCK_SKEW = 300

    class FieldError < Exception; end

    # site_id / key_id / nonce: printable tokens, no whitespace, no newlines.
    TOKEN_PATTERN = /\A[A-Za-z0-9._:-]{1,128}\z/

    def self.canonical(site_id : String, key_id : String, method : String,
                       path : String, body : Bytes, timestamp : Int64,
                       nonce : String) : Bytes
      check_token!("site_id", site_id)
      check_token!("key_id", key_id)
      check_token!("nonce", nonce)
      raise FieldError.new("method must be an HTTP token") unless method =~ /\A[A-Z]{3,10}\z/
      raise FieldError.new("path must start with / and contain no whitespace") unless path =~ /\A\/[^\s]*\z/

      String.build do |s|
        s << VERSION_TAG << '\n'
        s << site_id << '\n'
        s << key_id << '\n'
        s << method << '\n'
        s << path << '\n'
        s << Digest::SHA256.hexdigest(body) << '\n'
        s << timestamp << '\n'
        s << nonce
      end.to_slice
    end

    # Client side: produce the signature header value.
    def self.sign(key : Ed25519::SigningKey, site_id : String, key_id : String,
                  method : String, path : String, body : Bytes,
                  timestamp : Int64, nonce : String) : String
      Base64.strict_encode(key.sign(canonical(site_id, key_id, method, path, body, timestamp, nonce)))
    end

    # Server side: rebuild the canonical string from the request ACTUALLY
    # received and check the signature against it. Malformed input of any
    # kind — bad base64, bad field, wrong length — is a verification
    # failure, never an exception: attacker-controlled bytes must not pick
    # the code path.
    def self.verify?(key : Ed25519::VerifyKey, signature_b64 : String,
                     site_id : String, key_id : String, method : String,
                     path : String, body : Bytes, timestamp : Int64,
                     nonce : String) : Bool
      signature = Base64.decode(signature_b64)
      message = canonical(site_id, key_id, method, path, body, timestamp, nonce)
      key.verify?(message, signature)
    rescue Base64::Error | FieldError
      false
    end

    # Is the claimed timestamp within the accepted skew window of now?
    # Pure function of its inputs; the middleware passes the real clock.
    def self.fresh?(timestamp : Int64, now : Int64, max_skew : Int32 = MAX_CLOCK_SKEW) : Bool
      (now - timestamp).abs <= max_skew
    end

    # Client helper: a fresh single-use nonce.
    def self.generate_nonce : String
      Random::Secure.hex(16)
    end

    private def self.check_token!(name : String, value : String)
      raise FieldError.new("#{name} must match #{TOKEN_PATTERN.source}") unless value =~ TOKEN_PATTERN
    end
  end
end
