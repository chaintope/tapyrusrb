module Tapyrus
  # Key generation based on BIP-175
  #
  # @example
  #
  # master = Tapyrus::ExtKey.from_base58('xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73')
  # bip175 = Tapyrus::BIP175.from_private_key(master)
  # bip175 << "foo"
  # bip175 << "bar"
  # bip175.addr
  # > 1C7f322izqMqLzZzfzkPAjxBzprxDi47Yf
  #
  # @see https://github.com/bitcoin/bips/blob/master/bip-0175.mediawiki
  class BIP175
    PURPOSE_TYPE = 175

    attr_accessor :payment_base

    def initialize
      @contracts = []
    end

    # @param key [Tapyrus::ExtKey] master private extended key
    def self.from_ext_key(key)
      raise ArgumentError, 'key should be Tapyrus::ExtKey' unless key.is_a?(Tapyrus::ExtKey)
      new.tap do |bip175|
        bip175.payment_base =
          key.derive(PURPOSE_TYPE, true).derive(Tapyrus.chain_params.bip44_coin_type, true).ext_pubkey
      end
    end

    # @param key [Tapyrus::ExtPubkey] contract base public key
    def self.from_ext_pubkey(key)
      raise ArgumentError, 'key should be Tapyrus::ExtPubkey' unless key.is_a?(Tapyrus::ExtPubkey)
      new.tap { |bip175| bip175.payment_base = key }
    end

    # Add value of hashed contract
    # @param contract [String] contract information
    def add(contract)
      @contracts << Tapyrus.sha256(contract)
      self
    end
    alias << add

    # Return combined hash consist of payment_base and contract hashes
    # @return [String] contract_hash
    def combined_hash
      hashes = @contracts.map { |c| c.bth }.sort
      concatenated_hash = [payment_base.to_base58].concat(hashes).join
      Tapyrus.sha256(concatenated_hash)
    end

    # Return pay-to-contract extended public key
    # @return [Tapyrus::ExtPubkey] extended public key
    def pubkey
      # Split every 2 bytes
      paths = combined_hash.unpack('S>*')
      paths.inject(payment_base) { |key, p| key.derive(p) }
    end

    def addr
      pubkey.addr
    end
  end
end
