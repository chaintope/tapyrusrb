require 'siphash'
module Tapyrus
  module Message
    # BIP-152 Compact Block's data format.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki#HeaderAndShortIDs
    class HeaderAndShortIDs
      attr_accessor :header
      attr_accessor :nonce
      attr_accessor :short_ids
      attr_accessor :prefilled_txn
      attr_accessor :siphash_key

      def initialize(header, nonce, short_ids = [], prefilled_txn = [])
        @header = header
        @nonce = nonce
        @short_ids = short_ids
        @prefilled_txn = prefilled_txn
        @siphash_key = Tapyrus.sha256(header.to_payload << [nonce].pack('q*'))[0...16]
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header = Tapyrus::BlockHeader.parse_from_payload(buf)
        nonce = buf.read(8).unpack('q*').first
        short_ids_len = Tapyrus.unpack_var_int_from_io(buf)
        short_ids = short_ids_len.times.map { buf.read(6).reverse.bth.to_i(16) }
        prefilled_txn_len = Tapyrus.unpack_var_int_from_io(buf)
        prefilled_txn = prefilled_txn_len.times.map { PrefilledTx.parse_from_io(buf) }
        self.new(header, nonce, short_ids, prefilled_txn)
      end

      def to_payload
        p = header.to_payload
        p << [nonce].pack('q*')
        p << Tapyrus.pack_var_int(short_ids.size)
        p << short_ids.map { |id| sprintf('%12x', id).htb.reverse }.join
        p << Tapyrus.pack_var_int(prefilled_txn.size)
        p << prefilled_txn.map(&:to_payload).join
        p
      end

      # calculate short transaction id which specified by BIP-152.
      # @param [String] txid a transaction id
      # @return [Integer] 6 bytes short transaction id.
      def short_id(txid)
        hash = SipHash.digest(siphash_key, txid.htb.reverse).to_even_length_hex
        [hash].pack('H*')[2...8].bth.to_i(16)
      end
    end
  end
end
