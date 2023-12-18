module Tapyrus
  module JWS
    module_function

    class DecodeError < StandardError
    end

    ALGO = "ES256K"
    CURVE_NAME = "secp256k1"

    # Encode data as JWS format.
    #
    # @param payload [Object] The data to be encoded as JWS.
    # @param private_key_hex [String] The private key as hex string
    # @return [String] JWS signed with the specified private key
    def encode(payload, private_key_hex)
      parameters = { use: "sig", alg: ALGO }

      # see https://github.com/nov/json-jwt/blob/413848c/lib/json/jwk.rb#L162-L172
      # see https://www.rfc-editor.org/rfc/rfc5915.html#page-6
      sequence =
        OpenSSL::ASN1.Sequence(
          [
            OpenSSL::ASN1.Integer(1),
            OpenSSL::ASN1.OctetString(OpenSSL::BN.new(private_key_hex, 16).to_s(2)),
            OpenSSL::ASN1.ObjectId(CURVE_NAME, 0, :EXPLICIT),
            OpenSSL::ASN1.BitString(
              ECDSA::Format::PointOctetString.encode(point_for(private_key_hex), compression: false),
              1,
              :EXPLICIT
            )
          ]
        )
      ec_key = OpenSSL::PKey::EC.new(sequence.to_der)
      jwk = JWT::JWK.new(ec_key, parameters)
      jwks_hash = JWT::JWK::Set.new(jwk).export(include_private: false)
      JWT.encode(payload, jwk.signing_key, jwk[:alg], { typ: "JWT", algo: ALGO, jwk: jwks_hash })
    end

    # Decode JWS to JSON object
    #
    # @param jws [String] The JWS formatted data to be decoded
    # @return [Array[JSON]] JSON objects representing JWS header and payload.
    # @raise [JWT::VerificationError] If the verification of the signature fails
    # @raise [Tapyrus::JWS::DecodeError] If no jwk key found in header
    # @raise [Tapyrus::JWS::DecodeError] If jwk kty header is not EC
    # @raise [Tapyrus::JWS::DecodeError] If jwk crv header is not P-256K
    # @raise [Tapyrus::JWS::DecodeError] If jwk use header is not sig
    # @raise [Tapyrus::JWS::DecodeError] If jwk alg header is not ES256K
    def decode(jws)
      jwt_claims, header = JWT.decode(jws, nil, false, { algorithm: ALGO })
      jwks_hash = header.dig("jwk", "keys")
      raise Tapyrus::JWS::DecodeError, "No jwk key found in header" unless jwks_hash
      validate_header!(jwks_hash)
      jwks = JWT::JWK::Set.new(jwks_hash)
      JWT.decode(jws, nil, true, { algorithm: ALGO, jwks: jwks, allow_nil_kid: true })
    end

    def validate_header!(jwks)
      jwk = jwks.first
      raise Tapyrus::JWS::DecodeError, "No jwk key found in header" unless jwk
      raise Tapyrus::JWS::DecodeError, 'kty must be "EC"' if jwk["kty"] && jwk["kty"] != "EC"
      raise Tapyrus::JWS::DecodeError, 'crv must be "P-256K"' if jwk["crv"] && jwk["crv"] != "P-256K"
      raise Tapyrus::JWS::DecodeError, 'use must be "sig"' if jwk["use"] && jwk["use"] != "sig"
      raise Tapyrus::JWS::DecodeError, 'alg must be "ES256K"' if jwk["alg"] && jwk["alg"] != "ES256K"
    end

    # Return point object that represents rG
    #
    # @param r_hex [String] r value as hex string
    # @return [ECDSA::Point] The point that represents r * G
    def point_for(r_hex)
      Tapyrus::Key.new(priv_key: r_hex).to_point
    end
  end
end
