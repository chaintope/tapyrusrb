module Tapyrus
  module Message

    # tx message
    # https://bitcoin.org/en/developer-reference#tx
    class Tx < Base

      COMMAND = 'tx'

      attr_accessor :tx
      attr_accessor :use_segwit

      def initialize(tx, use_segwit = false)
        @tx = tx
        @use_segwit = use_segwit
      end

      def self.parse_from_payload(payload)
        tx = Tapyrus::Tx.parse_from_payload(payload)
        new(tx)
      end

      def to_payload
        tx.to_payload
      end

    end

  end
end
