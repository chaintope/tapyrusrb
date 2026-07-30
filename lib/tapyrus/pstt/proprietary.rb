module Tapyrus
  module PSTT
    # A proprietary record, for applications that need non-standardized fields.
    class Proprietary
      # @!attribute [r] identifier
      #   @return [String] the identifier of the proprietary type user with binary format.
      attr_reader :identifier

      # @!attribute [r] subtype
      #   @return [Integer] the subtype defined by the proprietary type user.
      attr_reader :subtype

      # @!attribute [r] subkeydata
      #   @return [String] the sub key data with binary format.
      attr_reader :subkeydata

      # @!attribute [rw] value
      #   @return [String] the value data with binary format.
      attr_accessor :value

      def initialize(identifier:, subtype:, subkeydata: "".b, value: "".b)
        @identifier = identifier
        @subtype = subtype
        @subkeydata = subkeydata
        @value = value
      end

      # Parse a proprietary record.
      # @param [Tapyrus::PSTT::KeyValue] record a record whose key type is 0xFC.
      # @return [Tapyrus::PSTT::Proprietary]
      def self.parse_from_record(record)
        buf = StringIO.new(record.keydata)
        identifier = PSTT.read_bytes(buf, PSTT.read_compact_size(buf))
        subtype = PSTT.read_compact_size(buf)
        new(identifier: identifier, subtype: subtype, subkeydata: buf.read || "".b, value: record.value)
      end

      # @return [String] the key data of this record with binary format.
      def to_keydata
        Tapyrus.pack_var_string(identifier) + Tapyrus.pack_var_int(subtype) + subkeydata
      end

      # @param [Integer] type the key type of the proprietary field in the map this record belongs to.
      # @return [Tapyrus::PSTT::KeyValue]
      def to_record(type)
        KeyValue.new(type, to_keydata, value)
      end

      def ==(other)
        other.is_a?(Proprietary) && to_keydata == other.to_keydata && value == other.value
      end
    end
  end
end
