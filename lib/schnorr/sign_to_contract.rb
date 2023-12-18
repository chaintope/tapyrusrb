module Schnorr
  module SignToContract
    module_function

    GROUP = ECDSA::Group::Secp256k1

    # Generate schnorr signature for sign-to-signature.
    # @param message [String] A message to be signed with binary format.
    # @param private_key [Integer] The private key.
    # @param contract [String] A contract information with 32-bytes binary format.
    # @return [(Schnorr::Signature, ECDSA::Point)] signature and point to prove the commitment to contract.
    def sign(message, private_key, contract)
      raise "The message must be a 32-byte array." unless message.bytesize == 32
      raise "private_key is zero or over the curve order." if private_key == 0 || private_key >= GROUP.order
      raise "The contract must be a 32-byte binary string." unless contract.bytesize == 32

      p = GROUP.new_point(private_key)
      k0 = Schnorr.deterministic_nonce(message, private_key)

      k1, r = tweak(k0, contract)

      q = GROUP.new_point(k1)
      k = ECDSA::PrimeField.jacobi(q.y, GROUP.field.prime) == 1 ? k1 : GROUP.order - k1

      e = Schnorr.create_challenge(q.x, p, message)

      [Schnorr::Signature.new(q.x, (k + e * private_key) % GROUP.order), r]
    end

    def tweak(k, contract)
      r = GROUP.new_point(k)
      rx = ECDSA::Format::IntegerOctetString.encode(r.x, GROUP.byte_length)
      h = Tapyrus.sha256(rx + contract)
      k1 = (k + h.bth.to_i(16)) % GROUP.order
      raise "Creation of signature failed. k + h(R || c) is zero" if k1.zero?
      [k1, r]
    end

    # Validate contract
    # @param r [ECDSA::Point] point to prove the commitment.
    # @param signature [Schnorr::Signature] signature.
    # @param contract [String]  A contract information with 32-bytes binary format.
    # @return true if commitment for contract is valid, otherwise false
    def valid_contract?(r, signature, contract)
      rx = ECDSA::Format::IntegerOctetString.encode(r.x, GROUP.byte_length)
      commitment = Tapyrus.sha256(rx + contract).bth.to_i(16) % GROUP.order
      point = r + GROUP.generator.multiply_by_scalar(commitment)
      signature.r == point.x
    end
  end
end
