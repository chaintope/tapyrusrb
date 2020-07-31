module Tapyrus
  module Message

    # block message
    # https://bitcoin.org/en/developer-reference#block
    class Block < Base

      attr_accessor :header
      attr_accessor :transactions
      attr_accessor :use_segwit

      COMMAND = 'block'

      def initialize(header, transactions = [])
        @header = header
        @transactions = transactions
        @use_segwit = false
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header = Tapyrus::BlockHeader.parse_from_payload(buf)
        transactions = []
        unless buf.eof?
          tx_count = Tapyrus.unpack_var_int_from_io(buf)
          tx_count.times do
            transactions << Tapyrus::Tx.parse_from_payload(buf)
          end
        end
        new(header, transactions)
      end

      def to_payload
        header.to_payload << Tapyrus.pack_var_int(transactions.size) <<
          transactions.map(&:to_payload).join
      end

      # generate Tapyrus::Block object.
      def to_block
        Tapyrus::Block.new(header, transactions)
      end

    end

  end
end
