module Tapyrus
  module Message

    # merckleblock message
    # https://bitcoin.org/en/developer-reference#merkleblock
    class MerkleBlock < Base

      COMMAND = 'merkleblock'

      attr_accessor :header
      attr_accessor :tx_count
      attr_accessor :hashes
      attr_accessor :flags

      def initialize
        @hashes = []
      end

      def self.parse_from_payload(payload)
        m = new
        buf = StringIO.new(payload)
        m.header = Tapyrus::BlockHeader.parse_from_payload(buf)
        m.tx_count = buf.read(4).unpack('V').first
        hash_count = Tapyrus.unpack_var_int_from_io(buf)
        hash_count.times do
          m.hashes << buf.read(32).bth
        end
        flag_count = Tapyrus.unpack_var_int_from_io(buf)
        # A sequence of bits packed eight in a byte with the least significant bit first.
        m.flags = buf.read(flag_count).bth
        m
      end

      def to_payload
        header.to_payload << [tx_count].pack('V') << Tapyrus.pack_var_int(hashes.size) <<
            hashes.map(&:htb).join << Tapyrus.pack_var_int(flags.htb.bytesize) << flags.htb
      end

    end

  end
end
