module Tapyrus

  # Block Header
  class BlockHeader
    include Tapyrus::HexConverter
    extend Tapyrus::Util
    include Tapyrus::Util

    X_FILED_TYPES = {none: 0, aggregate_pubkey: 1}

    attr_accessor :features
    attr_accessor :prev_hash
    attr_accessor :merkle_root
    attr_accessor :im_merkle_root # merkel root of immulable merkle tree which consist of immutable txid.
    attr_accessor :time           # unix timestamp
    attr_accessor :x_field_type
    attr_accessor :x_field
    attr_accessor :proof

    def initialize(features, prev_hash, merkle_root, im_merkle_root, time, x_field_type, x_field, proof = nil)
      @features = features
      @prev_hash = prev_hash
      @merkle_root = merkle_root
      @im_merkle_root = im_merkle_root
      @time = time
      @x_field_type = x_field_type
      @x_field = x_field
      @proof = proof
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      features, prev_hash, merkle_root, im_merkle_root, time, x_filed_type = buf.read(105).unpack('Va32a32a32Vc')
      x_field = buf.read(unpack_var_int_from_io(buf)) unless x_filed_type == X_FILED_TYPES[:none]
      proof = buf.read(unpack_var_int_from_io(buf))
      new(features, prev_hash.bth, merkle_root.bth, im_merkle_root.bth, time, x_filed_type, x_field ? x_field.bth : x_field, proof.bth)
    end

    def to_payload(skip_proof = false)
      payload = [features, prev_hash.htb, merkle_root.htb, im_merkle_root.htb, time, x_field_type].pack('Va32a32a32Vc')
      payload << pack_var_string(x_field.htb) unless x_field_type == X_FILED_TYPES[:none]
      payload << pack_var_string(proof.htb) if proof && !skip_proof
      payload
    end

    # Calculate hash using sign which does not contains proof.
    # @return [String] hash of block without proof.
    def hash_for_sign
      Tapyrus.double_sha256(to_payload(true)).bth
    end

    # Calculate block hash
    # @return [String] hash of block with hex format.
    def block_hash
      Tapyrus.double_sha256(to_payload).bth
    end

    # block hash(big endian)
    # @return [String] block id which is reversed version of block hash.
    def block_id
      block_hash.rhex
    end

    # evaluate block header
    # @param [String] agg_pubkey aggregated public key for signers with hex format.
    # @return [Boolean] result.
    def valid?(agg_pubkey)
      valid_timestamp? && valid_proof?(agg_pubkey) && valid_x_field?
    end

    # evaluate valid timestamp.
    # https://en.bitcoin.it/wiki/Block_timestamp
    def valid_timestamp?
      time <= Time.now.to_i + Tapyrus::MAX_FUTURE_BLOCK_TIME
    end

    # Check whether proof is valid.
    # @param [String] agg_pubkey aggregated public key for signers with hex format.
    # @return [Boolean] Return true if proof is valid, otherwise return false.
    def valid_proof?(agg_pubkey)
      pubkey = Tapyrus::Key.new(pubkey: agg_pubkey)
      msg = hash_for_sign.htb
      pubkey.verify(proof.htb, msg, algo: :schnorr)
    end

    # Check whether x_field is valid.
    # @return [Boolean] if valid return true, otherwise false
    def valid_x_field?
      case x_field_type
      when X_FILED_TYPES[:none] then
        x_field.nil?
      when X_FILED_TYPES[:aggregate_pubkey] then
        Tapyrus::Key.new(pubkey: x_field).fully_valid_pubkey?
      else
        false
      end
    end

    # Check this header contains upgrade aggregated publiec key.
    # @return [Boolean] if contains return true, otherwise false.
    def upgrade_agg_pubkey?
      x_field_type == X_FILED_TYPES[:aggregate_pubkey]
    end

    def ==(other)
      other && other.to_payload == to_payload
    end

    # get bytesize.
    # @return [Integer] bytesize.
    def size
      to_payload.bytesize
    end

  end

end