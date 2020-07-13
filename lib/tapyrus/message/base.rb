module Tapyrus
  module Message

    # Base message class
    class Base
      include Tapyrus::HexConverter
      include Tapyrus::Util
      extend Tapyrus::Util

      # generate message header (binary format)
      # https://bitcoin.org/en/developer-reference#message-headers
      def to_pkt
        payload = to_payload
        magic = Tapyrus.chain_params.magic_head.htb
        command_name = self.class.const_get(:COMMAND, false).ljust(12, "\x00")
        payload_size = [payload.bytesize].pack('V')
        checksum = Tapyrus.double_sha256(payload)[0...4]
        magic << command_name << payload_size << checksum << payload
      end

      # abstract method
      def to_payload
        raise 'to_payload must be implemented in a child class.'
      end

    end

  end
end
