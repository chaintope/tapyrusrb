module JWS
  module_function

  ALGO = 'ES256K'
  CURVE_NAME = 'secp256k1'

  # Encode data as JWS format.
  #
  # @param data [Object] The data to be encoded as JWS.
  # @param private_key_hex [String] private key as hex string
  # @return [String] JWS signed with the specified private key
  def encode(data, private_key_hex)
    # Private key to DER format
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
    JWT.encode(data, ec_key, ALGO, { typ: 'JWT' })
  end

  # Encode data as JWS format.
  #
  # @param data [Object] The data to be decoded
  # @param public_key_hex [String] public key as hex string
  # @return [String] JWS signed with the specified private key
  # @raise Verification signature failed
  def decode(data, public_key_hex = nil)
    unless public_key_hex
      jwt_claims, _header = JWT.decode(data, nil, false, { algorithm: ALGO })
      public_key_hex = jwt_claims['R']
    end

    sequence =
      OpenSSL::ASN1.Sequence(
        [
          OpenSSL::ASN1.Sequence([OpenSSL::ASN1.ObjectId('id-ecPublicKey'), OpenSSL::ASN1.ObjectId(CURVE_NAME)]),
          OpenSSL::ASN1.BitString(public_key_hex.htb)
        ]
      )
    ec_key = OpenSSL::PKey::EC.new(sequence.to_der)
    JWT.decode(data, ec_key, true, { algorithm: ALGO })
  end

  # Return point object that represents rG
  #
  # @param r_hex [String] r value as hex string
  # @return [ECDSA::Point] The point that represents r * G
  def point_for(r_hex)
    r = ECDSA::Format::IntegerOctetString.decode([r_hex].pack('H*'))
    g = ECDSA::Group::Secp256k1.generator
    g * r
  end
end
