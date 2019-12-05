module Tapyrus
  module Message

    # cmpctblock message. support only version 1.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
    class CmpctBlock < Base

      COMMAND = 'cmpctblock'

      attr_accessor :header_and_short_ids

      def initialize(header_and_short_ids)
        @header_and_short_ids = header_and_short_ids
      end

      # generate CmpctBlock from Block data.
      # @param [Tapyrus::Block] block the block to generate CmpctBlock.
      # @param [Integer] nonce
      # @return [Tapyrus::Message::CmpctBlock]
      def self.from_block(block, nonce = SecureRandom.hex(8).to_i(16))
        h = HeaderAndShortIDs.new(block.header, nonce)
        block.transactions[1..-1].each do |tx|
          h.short_ids << h.short_id(tx.txid)
        end
        h.prefilled_txn << PrefilledTx.new(0, block.transactions.first)
        self.new(h)
      end

      def self.parse_from_payload(payload)
        self.new(HeaderAndShortIDs.parse_from_payload(payload))
      end

      def to_payload
        header_and_short_ids.to_payload
      end

    end

  end
end
