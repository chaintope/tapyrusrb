module Schnorr
  autoload :Signature, 'schnorr/signature'

  module_function

  GROUP = ECDSA::Group::Secp256k1
  ALGO16 = 'SCHNORR + SHA256'

  # Generate schnorr signature.
  # @param message (String) A message to be signed with binary format.
  # @param private_key (Integer) The private key.
  # (The number of times to add the generator point to itself to get the public key.)
  # @return (Schnorr::Signature)
  def sign(message, private_key)
    raise 'The message must be a 32-byte array.' unless message.bytesize == 32
    raise 'private_key is zero or over the curve order.' if private_key == 0 || private_key >= GROUP.order

    p = GROUP.new_point(private_key)
    secret = ECDSA::Format::IntegerOctetString.encode(private_key, GROUP.byte_length)
    secret = secret + message + ALGO16
    nonce = Tapyrus::Secp256k1::RFC6979.generate_rfc6979_nonce(secret, '')

    k0 = nonce % GROUP.order
    raise 'Creation of signature failed. k is zero' if k0.zero?

    r = GROUP.new_point(k0)
    k = ECDSA::PrimeField.jacobi(r.y, GROUP.field.prime) == 1 ? k0 : GROUP.order - k0

    e = create_challenge(r.x, p, message)

    Schnorr::Signature.new(r.x, (k + e * private_key) % GROUP.order)
  end

  # Verifies the given {Signature} and returns true if it is valid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @return (Boolean) whether signature is valid.
  def valid_sig?(message, signature, public_key)
    check_sig!(message, signature, public_key)
  rescue InvalidSignatureError, ECDSA::Format::DecodeError
    false
  end

  # Verifies the given {Signature} and raises an {InvalidSignatureError} if it is invalid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @return (Boolean)
  def check_sig!(message, signature, public_key)
    sig = Schnorr::Signature.decode(signature)
    pubkey = ECDSA::Format::PointOctetString.decode(public_key, GROUP)
    field = GROUP.field

    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is not in the field.' unless field.include?(sig.r)
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is not in the field.' unless field.include?(sig.s)
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is larger than field size.' if sig.r >= field.prime
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is larger than group order.' if sig.s >= GROUP.order

    e = create_challenge(sig.r, pubkey, message)

    r = GROUP.new_point(sig.s) + pubkey.multiply_by_scalar(e).negate

    if r.infinity? || r.x != sig.r || ECDSA::PrimeField.jacobi(r.y, GROUP.field.prime) != 1
      raise Schnorr::InvalidSignatureError, 'signature verification failed.'
    end

    true
  end

  # create signature digest.
  # @param (Integer) x a x coordinate for R.
  # @param (ECDSA::Point) p a public key.
  # @return (Integer) digest e.
  def create_challenge(x, p, message)
    r_x = ECDSA::Format::IntegerOctetString.encode(x, GROUP.byte_length)
    p_str= p.to_hex.htb
    (ECDSA.normalize_digest(Digest::SHA256.digest(r_x + p_str + message), GROUP.bit_length)) % GROUP.order
  end

end