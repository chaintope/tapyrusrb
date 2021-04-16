module Tapyrus

  # outpoint class
  class OutPoint

    COINBASE_HASH = '0000000000000000000000000000000000000000000000000000000000000000'
    COINBASE_INDEX = 4294967295

    attr_reader :tx_hash
    attr_reader :index

    def initialize(tx_hash, index = -1)
      @tx_hash = tx_hash
      @index = index
    end

    def self.from_txid(txid, index)
      self.new(txid.rhex, index)
    end

    def coinbase?
      tx_hash == COINBASE_HASH
    end

    def to_payload
      [tx_hash.htb, index].pack('a32V')
    end

    def self.create_coinbase_outpoint
      new(COINBASE_HASH, COINBASE_INDEX)
    end

    def valid?
      index >= 0 && (!coinbase? && tx_hash != COINBASE_HASH)
    end

    def ==(other)
      to_payload == other&.to_payload
    end

    # convert hash to txid
    def txid
      tx_hash.rhex
    end

  end

end
