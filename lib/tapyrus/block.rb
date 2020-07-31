module Tapyrus
  class Block
    include Tapyrus::Util

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
    # @return [Integer] block height.
    def height
      transactions.first.in.first.out_point.index
    end

  end
end