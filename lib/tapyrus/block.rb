module Tapyrus
  class Block

    attr_accessor :header
    attr_accessor :transactions

    def initialize(header, transactions = [])
      @header = header
      @transactions = transactions
    end

    def self.parse_from_payload(payload)
      Tapyrus::Message::Block.parse_from_payload(payload).to_block
    end

    def hash
      header.hash
    end

    def block_hash
      header.block_hash
    end

    # check the merkle root in the block header matches merkle root calculated from tx list.
    def valid_merkle_root?
      calculate_merkle_root == header.merkle_root
    end

    # calculate merkle root from tx list.
    def calculate_merkle_root
      Tapyrus::MerkleTree.build_from_leaf(transactions.map(&:tx_hash)).merkle_root
    end

    # return this block height. block height is included in coinbase.
    # if block version under 1, height does not include in coinbase, so return nil.
    def height
      return nil if header.features < 2
      coinbase_tx = transactions[0]
      return nil unless coinbase_tx.coinbase_tx?
      buf = StringIO.new(coinbase_tx.inputs[0].script_sig.to_payload)
      len = Tapyrus.unpack_var_int_from_io(buf)
      buf.read(len).reverse.bth.to_i(16)
    end

  end
end