module Tapyrus
  module Store

    # wrap a block header object with extra data.
    class ChainEntry
      include Tapyrus::HexConverter

      attr_reader :header
      attr_reader :height

      # @param [Tapyrus::BlockHeader] header a block header.
      # @param [Integer] height a block height.
      def initialize(header, height)
        @header = header
        @height = height
      end

      # get database key
      def key
        Tapyrus::Store::KEY_PREFIX[:entry] + header.block_hash
      end

      def hash
        header.hash
      end

      # block hash
      def block_hash
        header.block_hash
      end

      # previous block hash
      def prev_hash
        header.prev_hash
      end

      # whether genesis block
      def genesis?
        height == 0
      end

      # @param [String] payload a payload with binary format.
      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        len = Tapyrus.unpack_var_int_from_io(buf)
        height = buf.read(len).reverse.bth.to_i(16)
        new(Tapyrus::BlockHeader.parse_from_payload(buf), height)
      end

      # build next block +StoredBlock+ instance.
      # @param [Tapyrus::BlockHeader] next_block a next block candidate header.
      # @return [Tapyrus::Store::ChainEntry] a next stored block (not saved).
      def build_next_block(next_block)
        ChainEntry.new(next_block, height + 1)
      end

      # generate payload
      def to_payload
        height_value = height.to_even_length_hex
        height_value = height_value.htb.reverse
        Tapyrus.pack_var_int(height_value.bytesize) + height_value + header.to_payload
      end

    end

  end

end
