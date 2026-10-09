# azb — client library for the Azooka Bay AZB1 signed-request protocol.
#
# This shard contains ONLY the protocol pieces every relying site needs:
# the Ed25519 binding and the canonical signing string. It is the same
# code the Azooka Bay server itself depends on, so a client's canonical
# string is byte-identical to the verifier's by construction.
#
# The AzookaBay namespace is preserved so server and sites share one
# module path: AzookaBay::Signing, AzookaBay::Ed25519.
#
# Protocol spec: docs/protocol.md. API reference: docs/api.md.
require "./azb/ed25519"
require "./azb/signing"
require "./azb/client"

module Azb
  VERSION = "0.3.0"
end
