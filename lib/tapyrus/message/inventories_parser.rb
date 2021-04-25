module Tapyrus
  module Message
    # Common message parser which only handle multiple inventory as payload.
    module InventoriesParser
      def parse_from_payload(payload)
        size, payload = Tapyrus.unpack_var_int(payload)
        buf = StringIO.new(payload)
        i = new
        size.times { i.inventories << Inventory.parse_from_payload(buf.read(36)) }
        i
      end

      def to_payload
        Tapyrus.pack_var_int(inventories.length) << inventories.map(&:to_payload).join
      end
    end
  end
end
