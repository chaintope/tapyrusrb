module Tapyrus
  module Message
    # headers message
    # https://bitcoin.org/en/developer-reference#headers
    class Headers < Base
      COMMAND = 'headers'

      # Array[Tapyrus::BlockHeader]
      attr_accessor :headers

      def initialize(headers = [])
        @headers = headers
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header_count = Tapyrus.unpack_var_int_from_io(buf)
        h = new
        header_count.times do
          h.headers << Tapyrus::BlockHeader.parse_from_payload(buf)
          buf.read(1) # read tx count 0x00 (headers message doesn't include any tx.)
        end
        h
      end

      def to_payload
        Tapyrus.pack_var_int(headers.size) << headers.map { |h| h.to_payload << 0x00 }.join
      end
    end
  end
end
