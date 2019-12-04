module Tapyrus

  module Descriptor

    include Tapyrus::Opcodes

    # generate P2PK output for the given public key.
    # @param [String] key private key or public key with hex format
    # @return [Tapyrus::Script] P2PK script.
    def pk(key)
      Tapyrus::Script.new << extract_pubkey(key) << OP_CHECKSIG
    end

    # generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Tapyrus::Script] P2PKH script.
    def pkh(key)
      Tapyrus::Script.to_p2pkh(Tapyrus.hash160(extract_pubkey(key)))
    end

    # generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Tapyrus::Script] P2WPKH script.
    def wpkh(key)
      pubkey = extract_pubkey(key)
      raise ArgumentError, "Uncompressed key are not allowed." unless compressed_key?(pubkey)
      Tapyrus::Script.to_p2wpkh(Tapyrus.hash160(pubkey))
    end

    # generate P2SH embed the argument.
    # @param [String or Script] script script to be embed.
    # @return [Tapyrus::Script] P2SH script.
    def sh(script)
      script = script.to_hex if script.is_a?(Tapyrus::Script)
      raise ArgumentError, "P2SH script is too large, 547 bytes is larger than #{Tapyrus::MAX_SCRIPT_ELEMENT_SIZE} bytes." if script.htb.bytesize > Tapyrus::MAX_SCRIPT_ELEMENT_SIZE
      Tapyrus::Script.to_p2sh(Tapyrus.hash160(script))
    end

    # generate P2WSH embed the argument.
    # @param [String or Script] script script to be embed.
    # @return [Tapyrus::Script] P2WSH script.
    def wsh(script)
      script = Tapyrus::Script(script.htb) if script.is_a?(String)
      raise ArgumentError, "P2SH script is too large, 547 bytes is larger than #{Tapyrus::MAX_SCRIPT_ELEMENT_SIZE} bytes." if script.to_payload.bytesize > Tapyrus::MAX_SCRIPT_ELEMENT_SIZE
      raise ArgumentError, "Uncompressed key are not allowed." if script.get_pubkeys.any?{|p|!compressed_key?(p)}
      Tapyrus::Script.to_p2wsh(script)
    end

    # an alias for the collection of `pk(KEY)` and `pkh(KEY)`.
    # If the key is compressed, it also includes `wpkh(KEY)` and `sh(wpkh(KEY))`.
    # @param [String] key private key or public key with hex format.
    # @return [Array[Tapyrus::Script]]
    def combo(key)
      result = [pk(key), pkh(key)]
      pubkey = extract_pubkey(key)
      if compressed_key?(pubkey)
        result << wpkh(key)
        result << sh(result.last)
      end
      result
    end

    # generate multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Tapyrus::Script] multisig script.
    def multi(threshold, *keys, sort: false)
      raise ArgumentError, 'Multisig threshold is not valid.' unless threshold.is_a?(Integer)
      raise ArgumentError, 'Multisig threshold cannot be 0, must be at least 1.' unless threshold > 0
      raise ArgumentError, 'Multisig threshold cannot be larger than the number of keys.' if threshold > keys.size
      raise ArgumentError, 'Multisig must have between 1 and 16 keys, inclusive.' if keys.size > 16
      pubkeys = keys.map{|key| extract_pubkey(key) }
      Tapyrus::Script.to_multisig_script(threshold, pubkeys, sort: sort)
    end

    # generate sorted multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Tapyrus::Script] multisig script.
    def sortedmulti(threshold, *keys)
      multi(threshold, *keys, sort: true)
    end

    private

    # extract public key from KEY format.
    # @param [String] key KEY string.
    # @return [String] public key.
    def extract_pubkey(key)
      if key.start_with?('[') # BIP32 fingerprint
        raise ArgumentError, 'Invalid key origin.' if key.count('[') > 1 || key.count(']') > 1
        info = key[1...key.index(']')] # TODO
        fingerprint, *paths = info.split('/')
        raise ArgumentError, 'Fingerprint is not hex.' unless fingerprint.valid_hex?
        raise ArgumentError, 'Fingerprint is not 4 bytes.' unless fingerprint.size == 8
        key = key[(key.index(']') + 1)..-1]
      else
        raise ArgumentError, 'Invalid key origin.' if key.include?(']')
      end

      # check BIP32 derivation path
      key, *paths = key.split('/')

      if key.start_with?('xprv')
        key = Tapyrus::ExtKey.from_base58(key)
        key = derive_path(key, paths, true) if paths
      elsif key.start_with?('xpub')
        key = Tapyrus::ExtPubkey.from_base58(key)
        key = derive_path(key, paths, false) if paths
      else
        begin
          key = Tapyrus::Key.from_wif(key)
        rescue ArgumentError
          key_type =  compressed_key?(key) ? Tapyrus::Key::TYPES[:compressed] : Tapyrus::Key::TYPES[:uncompressed]
          key = Tapyrus::Key.new(pubkey: key, key_type: key_type)
        end
      end
      key = key.is_a?(Tapyrus::Key) ? key : key.key
      raise ArgumentError, 'Invalid pubkey.' unless key.fully_valid_pubkey?
      key.pubkey
    end

    def compressed_key?(key)
      %w(02 03).include?(key[0..1]) && [key].pack("H*").bytesize == 33
    end

    def derive_path(key, paths, is_private)
      paths.each do |path|
        raise ArgumentError, 'xpub can not derive hardened key.' if !is_private && path.end_with?("'")
        if is_private
          hardened = path.end_with?("'")
          path = hardened ? path[0..-2] : path
          raise ArgumentError, 'Key path value is not a valid value.' unless path =~ /^[0-9]+$/
          raise ArgumentError, 'Key path value is out of range.' if !hardened && path.to_i >= Tapyrus::HARDENED_THRESHOLD
          key = key.derive(path.to_i, hardened)
        else
          raise ArgumentError, 'Key path value is not a valid value.' unless path =~ /^[0-9]+$/
          raise ArgumentError, 'Key path value is out of range.' if path.to_i >= Tapyrus::HARDENED_THRESHOLD
          key = key.derive(path.to_i)
        end
      end
      key
    end

  end

end