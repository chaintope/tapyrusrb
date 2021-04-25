module Tapyrus
  # Integers modulo the order of the curve(secp256k1)
  CURVE_ORDER = ECDSA::Group::Secp256k1.order

  # BIP32 Extended private key
  class ExtKey
    include Tapyrus::HexConverter

    MAX_DEPTH = 255
    MASTER_FINGERPRINT = '00000000'

    attr_accessor :ver
    attr_accessor :depth
    attr_accessor :number
    attr_accessor :chain_code
    attr_accessor :key # Tapyrus::Key
    attr_accessor :parent_fingerprint

    # generate master key from seed.
    # @params [String] seed a seed data with hex format.
    def self.generate_master(seed)
      ext_key = ExtKey.new
      ext_key.depth = ext_key.number = 0
      ext_key.parent_fingerprint = '00000000'
      l = Tapyrus.hmac_sha512('Tapyrus seed', seed.htb)
      left = l[0..31].bth.to_i(16)
      raise 'invalid key' if left >= CURVE_ORDER || left == 0
      ext_key.key = Tapyrus::Key.new(priv_key: l[0..31].bth, key_type: Tapyrus::Key::TYPES[:compressed])
      ext_key.chain_code = l[32..-1]
      ext_key
    end

    # get ExtPubkey from priv_key
    def ext_pubkey
      k = ExtPubkey.new
      k.depth = depth
      k.number = number
      k.parent_fingerprint = parent_fingerprint
      k.chain_code = chain_code
      k.pubkey = key.pubkey
      k.ver = priv_ver_to_pub_ver
      k
    end

    # serialize extended private key
    def to_payload
      version.htb << [depth].pack('C') << parent_fingerprint.htb << [number].pack('N') << chain_code <<
        [0x00].pack('C') << key.priv_key.htb
    end

    # Base58 encoded extended private key
    def to_base58
      ExtPubkey.encode_base58(to_hex)
    end

    # get private key(hex)
    def priv
      key.priv_key
    end

    # get public key(hex)
    def pub
      key.pubkey
    end

    def hash160
      Tapyrus.hash160(pub)
    end

    # get address
    def addr
      ext_pubkey.addr
    end

    # get key identifier
    def identifier
      Tapyrus.hash160(key.pubkey)
    end

    # get fingerprint
    def fingerprint
      identifier.slice(0..7)
    end

    # whether hardened key.
    def hardened?
      number >= Tapyrus::HARDENED_THRESHOLD
    end

    # derive new key
    # @param [Integer] number a child index
    # @param [Boolean] harden whether hardened key or not. If true, 2^31 is added to +number+.
    # @return [Tapyrus::ExtKey] derived new key.
    def derive(number, harden = false)
      number += Tapyrus::HARDENED_THRESHOLD if harden
      new_key = ExtKey.new
      new_key.depth = depth + 1
      new_key.number = number
      new_key.parent_fingerprint = fingerprint
      if number > (Tapyrus::HARDENED_THRESHOLD - 1)
        data = [0x00].pack('C') << key.priv_key.htb << [number].pack('N')
      else
        data = key.pubkey.htb << [number].pack('N')
      end
      l = Tapyrus.hmac_sha512(chain_code, data)
      left = l[0..31].bth.to_i(16)
      raise 'invalid key' if left >= CURVE_ORDER
      child_priv = (left + key.priv_key.to_i(16)) % CURVE_ORDER
      raise 'invalid key ' if child_priv >= CURVE_ORDER
      new_key.key = Tapyrus::Key.new(priv_key: child_priv.to_even_length_hex.rjust(64, '0'), key_type: key_type)
      new_key.chain_code = l[32..-1]
      new_key.ver = version
      new_key
    end

    # get version bytes using serialization format
    def version
      return ExtKey.version_from_purpose(number) if depth == 1
      ver ? ver : Tapyrus.chain_params.extended_privkey_version
    end

    # get key type defined by BIP-178 using version.
    def key_type
      v = version
      case v
      when Tapyrus.chain_params.bip49_privkey_p2wpkh_p2sh_version
        Tapyrus::Key::TYPES[:p2wpkh_p2sh]
      when Tapyrus.chain_params.bip84_privkey_p2wpkh_version
        Tapyrus::Key::TYPES[:p2wpkh]
      when Tapyrus.chain_params.extended_privkey_version
        Tapyrus::Key::TYPES[:compressed]
      end
    end

    def ==(other)
      to_payload == other.to_payload
    end

    def self.parse_from_payload(payload)
      buf = StringIO.new(payload)
      ext_key = ExtKey.new
      ext_key.ver = buf.read(4).bth # version
      raise ArgumentError, Errors::Messages::INVALID_BIP32_VERSION unless ExtKey.support_version?(ext_key.ver)
      ext_key.depth = buf.read(1).unpack('C').first
      ext_key.parent_fingerprint = buf.read(4).bth
      ext_key.number = buf.read(4).unpack('N').first
      if ext_key.depth == 0
        unless ext_key.parent_fingerprint == ExtKey::MASTER_FINGERPRINT
          raise ArgumentError, Errors::Messages::INVALID_BIP32_FINGERPRINT
        end
        raise ArgumentError, Errors::Messages::INVALID_BIP32_ZERO_INDEX if ext_key.number > 0
      end
      if ext_key.parent_fingerprint == ExtKey::MASTER_FINGERPRINT && ext_key.depth > 0
        raise ArgumentError, Errors::Messages::INVALID_BIP32_ZERO_DEPTH
      end
      ext_key.chain_code = buf.read(32)
      raise ArgumentError, Errors::Messages::INVALID_BIP32_PRIV_PREFIX unless buf.read(1).bth == '00' # 0x00
      ext_key.key = Tapyrus::Key.new(priv_key: buf.read(32).bth, key_type: Tapyrus::Key::TYPES[:compressed])
      ext_key
    end

    # import private key from Base58 private key address
    def self.from_base58(address)
      ExtKey.parse_from_payload(ExtPubkey.validate_checksum(address))
    end

    # get version bytes from purpose' value.
    def self.version_from_purpose(purpose)
      v = purpose - Tapyrus::HARDENED_THRESHOLD
      case v
      when 49
        Tapyrus.chain_params.bip49_privkey_p2wpkh_p2sh_version
      when 84
        Tapyrus.chain_params.bip84_privkey_p2wpkh_version
      else
        Tapyrus.chain_params.extended_privkey_version
      end
    end

    # check whether +version+ is supported version bytes.
    def self.support_version?(version)
      p = Tapyrus.chain_params
      [p.bip49_privkey_p2wpkh_p2sh_version, p.bip84_privkey_p2wpkh_version, p.extended_privkey_version].include?(
        version
      )
    end

    # convert privkey version to pubkey version
    def priv_ver_to_pub_ver
      case version
      when Tapyrus.chain_params.bip49_privkey_p2wpkh_p2sh_version
        Tapyrus.chain_params.bip49_pubkey_p2wpkh_p2sh_version
      when Tapyrus.chain_params.bip84_privkey_p2wpkh_version
        Tapyrus.chain_params.bip84_pubkey_p2wpkh_version
      else
        Tapyrus.chain_params.extended_pubkey_version
      end
    end
  end

  # BIP-32 Extended public key
  class ExtPubkey
    include Tapyrus::HexConverter

    attr_accessor :ver
    attr_accessor :depth
    attr_accessor :number
    attr_accessor :chain_code
    attr_accessor :pubkey # hex format
    attr_accessor :parent_fingerprint

    # serialize extended pubkey
    def to_payload
      version.htb << [depth].pack('C') << parent_fingerprint.htb << [number].pack('N') << chain_code << pub.htb
    end

    def pub
      pubkey
    end

    def hash160
      Tapyrus.hash160(pub)
    end

    # get address
    def addr
      key.to_p2pkh
    end

    # get key object
    # @return [Tapyrus::Key]
    def key
      Tapyrus::Key.new(pubkey: pubkey, key_type: key_type)
    end

    # get key identifier
    def identifier
      Tapyrus.hash160(pub)
    end

    # get fingerprint
    def fingerprint
      identifier.slice(0..7)
    end

    # Base58 encoded extended pubkey
    def to_base58
      ExtPubkey.encode_base58(to_hex)
    end

    # Generate Base58 encoded key from BIP32 payload with hex format.
    # @param [String] hex BIP32 payload with hex format.
    # @return [String] Base58 encoded extended key.
    def self.encode_base58(hex)
      Base58.encode(hex + Tapyrus.calc_checksum(hex))
    end

    # whether hardened key.
    def hardened?
      number >= Tapyrus::HARDENED_THRESHOLD
    end

    # derive child key
    def derive(number)
      new_key = ExtPubkey.new
      new_key.depth = depth + 1
      new_key.number = number
      new_key.parent_fingerprint = fingerprint
      raise 'hardened key is not support' if number > (Tapyrus::HARDENED_THRESHOLD - 1)
      data = pub.htb << [number].pack('N')
      l = Tapyrus.hmac_sha512(chain_code, data)
      left = l[0..31].bth.to_i(16)
      raise 'invalid key' if left >= CURVE_ORDER
      p1 = Tapyrus::Secp256k1::GROUP.generator.multiply_by_scalar(left)
      p2 = Tapyrus::Key.new(pubkey: pubkey, key_type: key_type).to_point
      new_key.pubkey = (p1 + p2).to_hex
      new_key.chain_code = l[32..-1]
      new_key.ver = version
      new_key
    end

    # get version bytes using serialization format
    def version
      return ExtPubkey.version_from_purpose(number) if depth == 1
      ver ? ver : Tapyrus.chain_params.extended_pubkey_version
    end

    # get key type defined by BIP-178 using version.
    def key_type
      v = version
      case v
      when Tapyrus.chain_params.bip49_pubkey_p2wpkh_p2sh_version
        Tapyrus::Key::TYPES[:p2wpkh_p2sh]
      when Tapyrus.chain_params.bip84_pubkey_p2wpkh_version
        Tapyrus::Key::TYPES[:p2wpkh]
      when Tapyrus.chain_params.extended_pubkey_version
        Tapyrus::Key::TYPES[:compressed]
      end
    end

    def ==(other)
      to_payload == other.to_payload
    end

    def self.parse_from_payload(payload)
      buf = StringIO.new(payload)
      ext_pubkey = ExtPubkey.new
      ext_pubkey.ver = buf.read(4).bth # version
      raise ArgumentError, Errors::Messages::INVALID_BIP32_VERSION unless ExtPubkey.support_version?(ext_pubkey.ver)
      ext_pubkey.depth = buf.read(1).unpack('C').first
      ext_pubkey.parent_fingerprint = buf.read(4).bth
      ext_pubkey.number = buf.read(4).unpack('N').first
      if ext_pubkey.depth == 0
        unless ext_pubkey.parent_fingerprint == ExtKey::MASTER_FINGERPRINT
          raise ArgumentError, Errors::Messages::INVALID_BIP32_FINGERPRINT
        end
        raise ArgumentError, Errors::Messages::INVALID_BIP32_ZERO_INDEX if ext_pubkey.number > 0
      end
      if ext_pubkey.parent_fingerprint == ExtKey::MASTER_FINGERPRINT && ext_pubkey.depth > 0
        raise ArgumentError, Errors::Messages::INVALID_BIP32_ZERO_DEPTH
      end
      ext_pubkey.chain_code = buf.read(32)
      ext_pubkey.pubkey = Tapyrus::Key.new(pubkey: buf.read(33).bth).pubkey
      ext_pubkey
    end

    # import pub key from Base58 private key address
    def self.from_base58(address)
      ExtPubkey.parse_from_payload(ExtPubkey.validate_checksum(address))
    end

    # Validate address checksum and return payload.
    # @param [String] BIP32 Base58 address
    # @return [String] BIP32 payload with binary format
    def self.validate_checksum(base58)
      raw = Base58.decode(base58)
      raise ArgumentError, Errors::Messages::INVALID_CHECKSUM unless Tapyrus.calc_checksum(raw[0...-8]) == raw[-8..-1]
      raw[0...-8].htb
    end

    # get version bytes from purpose' value.
    def self.version_from_purpose(purpose)
      v = purpose - Tapyrus::HARDENED_THRESHOLD
      case v
      when 49
        Tapyrus.chain_params.bip49_pubkey_p2wpkh_p2sh_version
      when 84
        Tapyrus.chain_params.bip84_pubkey_p2wpkh_version
      else
        Tapyrus.chain_params.extended_pubkey_version
      end
    end

    # check whether +version+ is supported version bytes.
    def self.support_version?(version)
      p = Tapyrus.chain_params
      [p.bip49_pubkey_p2wpkh_p2sh_version, p.bip84_pubkey_p2wpkh_version, p.extended_pubkey_version].include?(version)
    end
  end
end
