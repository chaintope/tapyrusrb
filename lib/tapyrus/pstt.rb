module Tapyrus
  # Partially Signed Tapyrus Transaction (PSTT) defined by TIP-0174.
  #
  # A PSTT holds a not-yet-signed Tapyrus transaction together with the metadata signers need.
  # The data model follows BIP-370: the transaction is represented by per-input and per-output
  # fields, so inputs and outputs can be added after creation.
  module PSTT
    autoload :Input, "tapyrus/pstt/input"
    autoload :KeyOriginInfo, "tapyrus/pstt/key_origin_info"
    autoload :Output, "tapyrus/pstt/output"
    autoload :Proprietary, "tapyrus/pstt/proprietary"
    autoload :Tx, "tapyrus/pstt/tx"

    # The magic bytes which begin every PSTT. ASCII "pstt" followed by the separator 0xFF.
    MAGIC = "70737474ff".htb

    # The only version this TIP defines.
    VERSION = 0

    # The boundary between height-based and time-based locktime.
    LOCKTIME_THRESHOLD = 500_000_000

    # The sighash types TIP-0174 defines: SIGHASH_ALL, SIGHASH_NONE and SIGHASH_SINGLE, each
    # optionally combined with SIGHASH_ANYONECANPAY.
    SIGHASH_BASE_TYPES = [SIGHASH_TYPE[:all], SIGHASH_TYPE[:none], SIGHASH_TYPE[:single]].freeze
    SIGHASH_TYPES = (SIGHASH_BASE_TYPES + SIGHASH_BASE_TYPES.map { |t| t | SIGHASH_TYPE[:anyonecanpay] }).freeze

    # Global map key types.
    module GlobalTypes
      # Reserved. The global unsigned transaction of BIP-174 has no counterpart in this format.
      UNSIGNED_TX = 0x00
      XPUB = 0x01
      TX_FEATURES = 0x02
      FALLBACK_LOCKTIME = 0x03
      INPUT_COUNT = 0x04
      OUTPUT_COUNT = 0x05
      TX_MODIFIABLE = 0x06
      VERSION = 0xfb
      PROPRIETARY = 0xfc
    end

    # Input map key types.
    module InputTypes
      UTXO = 0x00
      PARTIAL_SIG = 0x02
      SIGHASH_TYPE = 0x03
      REDEEM_SCRIPT = 0x04
      BIP32_DERIVATION = 0x06
      FINAL_SCRIPTSIG = 0x07
      RIPEMD160 = 0x0a
      SHA256 = 0x0b
      HASH160 = 0x0c
      HASH256 = 0x0d
      PREVIOUS_TXID = 0x0e
      OUTPUT_INDEX = 0x0f
      SEQUENCE = 0x10
      REQUIRED_TIME_LOCKTIME = 0x11
      REQUIRED_HEIGHT_LOCKTIME = 0x12
      PROPRIETARY = 0xfc

      # Segregated Witness(0x01, 0x05, 0x08, 0x09) and Taproot(0x13..0x18, defined by BIP-371)
      # key types. They have no meaning in Tapyrus. Key types which BIPs later assigned to
      # MuSig2 and other schemes are not listed here, so that they are carried through as
      # unknown records rather than rejected.
      RESERVED = [0x01, 0x05, 0x08, 0x09, *(0x13..0x18)].freeze
    end

    # Output map key types.
    module OutputTypes
      REDEEM_SCRIPT = 0x00
      BIP32_DERIVATION = 0x02
      AMOUNT = 0x03
      SCRIPT = 0x04
      PROPRIETARY = 0xfc

      # Segregated Witness(0x01) and Taproot(0x05..0x07, defined by BIP-371) key types.
      # They have no meaning in Tapyrus. See InputTypes::RESERVED.
      RESERVED = [0x01, *(0x05..0x07)].freeze
    end

    # The bitfield of PSTT_GLOBAL_TX_MODIFIABLE.
    module TxModifiable
      INPUTS = 0x01
      OUTPUTS = 0x02
      HAS_SIGHASH_SINGLE = 0x04
      ALL = INPUTS | OUTPUTS | HAS_SIGHASH_SINGLE
    end

    # Raised when a PSTT is malformed, or when an operation violates a rule of TIP-0174.
    class Error < StandardError
    end

    # A single key-value record of a PSTT map.
    KeyValue =
      Struct.new(:type, :keydata, :value) do
        # The complete key(<keytype> and <keydata>). Records are unique by this value within a map.
        # @return [String] the complete key with binary format.
        def key
          Tapyrus.pack_var_int(type) + keydata
        end

        def to_payload
          k = key
          Tapyrus.pack_var_int(k.bytesize) + k + Tapyrus.pack_var_int(value.bytesize) + value
        end
      end

    class << self
      # Read a compact size unsigned integer from +buf+.
      #
      # Every compact size integer of the format must be minimally encoded. TIP-0174 states the
      # requirement for <keytype>, and holding the whole container to it is what makes the byte
      # representation of a PSTT unique: two encodings of the same length would otherwise produce
      # two different byte strings carrying the same records. It also removes the need to treat
      # the map separator specially, since a non-minimally encoded 0 is rejected here.
      # @param [StringIO] buf a buffer.
      # @return [Integer] the value.
      # @raise [Tapyrus::PSTT::Error] if the buffer is truncated or the encoding is not minimal.
      def read_compact_size(buf)
        prefix = read_bytes(buf, 1).unpack1("C")
        case prefix
        when 0xfd
          value = read_bytes(buf, 2).unpack1("v")
          raise Error, "compact size is not minimally encoded." if value < 0xfd
        when 0xfe
          value = read_bytes(buf, 4).unpack1("V")
          raise Error, "compact size is not minimally encoded." if value <= 0xffff
        when 0xff
          value = read_bytes(buf, 8).unpack1("Q<")
          raise Error, "compact size is not minimally encoded." if value <= 0xffffffff
        else
          value = prefix
        end
        value
      end

      # Read exactly +size+ bytes from +buf+.
      # @param [StringIO] buf a buffer.
      # @param [Integer] size the byte size to be read.
      # @return [String] the read data with binary format.
      # @raise [Tapyrus::PSTT::Error] if the buffer holds fewer bytes.
      def read_bytes(buf, size)
        data = buf.read(size)
        raise Error, "PSTT payload is truncated." if data.nil? || data.bytesize != size
        data
      end

      # Parse a single map, which is a sequence of key-value records terminated by 0x00.
      # @param [StringIO] buf a buffer.
      # @return [Array[Tapyrus::PSTT::KeyValue]] the records of the map.
      # @raise [Tapyrus::PSTT::Error] if the map is malformed.
      def parse_map(buf)
        records = []
        keys = {}
        loop do
          raise Error, "PSTT map is not terminated." if buf.eof?
          key_len = read_compact_size(buf)
          break if key_len.zero? # the 0x00 separator
          key = read_bytes(buf, key_len)
          key_buf = StringIO.new(key)
          type = read_compact_size(key_buf)
          keydata = key_buf.read || ""
          raise Error, "PSTT map contains a duplicated key." if keys.key?(key)
          keys[key] = true
          value_len = read_compact_size(buf)
          records << KeyValue.new(type, keydata, read_bytes(buf, value_len))
        end
        records
      end

      # Serialize +records+ as a map.
      # @param [Array[Tapyrus::PSTT::KeyValue]] records the records of the map.
      # @param [Array[String]] order the complete keys of the map this PSTT was parsed from.
      # @return [String] the serialized map with binary format.
      def serialize_map(records, order = nil)
        order_records(records, order).map(&:to_payload).join + "\x00".b
      end

      # Put +records+ back into the order the map was parsed in, so that parsing a PSTT and
      # serializing it again yields the same bytes. TIP-0174 prescribes no order - either order is
      # a valid PSTT carrying the same records - but a byte-stable round trip lets a caller hash,
      # cache or diff a PSTT without normalizing it first. A record which was not in the parsed
      # map, such as a signature collected since, follows the records which were, in the order
      # this implementation generates them. A map which was not parsed is emitted in ascending
      # order of the complete key.
      # @param [Array[Tapyrus::PSTT::KeyValue]] records the records of the map.
      # @param [Array[String]] order the complete keys of the map this PSTT was parsed from.
      # @return [Array[Tapyrus::PSTT::KeyValue]] the ordered records.
      def order_records(records, order)
        return records.sort_by { |r| [r.type, r.keydata] } if order.nil? || order.empty?
        rank = {}
        order.each_with_index { |key, i| rank[key] ||= i }
        records.each_with_index.sort_by { |record, i| [rank.fetch(record.key, order.size + i), i] }.map(&:first)
      end

      # Check that +record+ has no key data, as its field definition requires.
      # @param [Tapyrus::PSTT::KeyValue] record a record.
      # @raise [Tapyrus::PSTT::Error] if the record has key data.
      def validate_empty_keydata!(record)
        raise Error, format("keydata for type 0x%02x must be empty.", record.type) unless record.keydata.empty?
      end

      # Check that the key data of +record+ is a public key.
      # @param [Tapyrus::PSTT::KeyValue] record a record.
      # @raise [Tapyrus::PSTT::Error] if the key data is not a 33- or 65-byte public key.
      def validate_pubkey_keydata!(record)
        size = record.keydata.bytesize
        unless [Tapyrus::Key::COMPRESSED_PUBLIC_KEY_SIZE, Tapyrus::Key::PUBLIC_KEY_SIZE].include?(size)
          raise Error,
                format("keydata for type 0x%02x must be a 33- or 65-byte public key, but %d bytes.", record.type, size)
        end
      end

      # Check that the value of +record+ has +size+ bytes.
      # @param [Tapyrus::PSTT::KeyValue] record a record.
      # @param [Integer] size the required byte size.
      # @raise [Tapyrus::PSTT::Error] if the value has another size.
      def validate_value_size!(record, size)
        unless record.value.bytesize == size
          raise Error,
                format(
                  "value for type 0x%02x must be %d bytes, but %d bytes.",
                  record.type,
                  size,
                  record.value.bytesize
                )
        end
      end

      # Read a 32-bit little endian unsigned integer from the value of +record+.
      def read_u32(record)
        validate_value_size!(record, 4)
        record.value.unpack1("V")
      end

      # Read a 32-bit little endian signed integer from the value of +record+.
      def read_i32(record)
        validate_value_size!(record, 4)
        record.value.unpack1("l<")
      end

      # Read a 64-bit little endian signed integer from the value of +record+.
      def read_i64(record)
        validate_value_size!(record, 8)
        record.value.unpack1("q<")
      end

      # Read an 8-bit unsigned integer from the value of +record+.
      def read_u8(record)
        validate_value_size!(record, 1)
        record.value.unpack1("C")
      end

      # Read a compact size unsigned integer from the value of +record+.
      def read_count(record)
        buf = StringIO.new(record.value)
        count = read_compact_size(buf)
        raise Error, format("value for type 0x%02x is not a compact size uint.", record.type) unless buf.eof?
        count
      end

      # Parse the value or the key data of a record with +block+, and report any failure as a
      # Tapyrus::PSTT::Error. The records of a PSTT come from another party, so a malformed one
      # must not surface as an exception of the parser the field happens to be built on.
      # @param [String] name the name of the field, used in the error message.
      # @raise [Tapyrus::PSTT::Error] if the block raises.
      def parse_field(name)
        yield
      rescue Error
        raise
      rescue StandardError => e
        raise Error, "#{name} is malformed. #{e.message}"
      end

      # Check that +hash_type+ is one of the sighash types TIP-0174 defines.
      # @param [Integer] hash_type a sighash type.
      # @raise [Tapyrus::PSTT::Error] if it is not.
      def validate_sighash_type!(hash_type)
        unless SIGHASH_TYPES.include?(hash_type)
          raise Error, format("Sighash type 0x%x is not defined by TIP-0174.", hash_type)
        end
      end

      # Check that +amount+ is within the range Tapyrus allows.
      # @param [Integer] amount an amount of tapy or of tokens.
      # @raise [Tapyrus::PSTT::Error] if it is not.
      def validate_amount!(amount)
        unless amount.is_a?(Integer) && amount >= 0 && amount <= MAX_MONEY
          raise Error, "PSTT_OUT_AMOUNT must be between 0 and #{MAX_MONEY}, but #{amount}."
        end
      end

      # Check that +features+ is a positive value. Tapyrus currently defines only 1, but a
      # transaction feature which a later version adds is accepted so that this implementation
      # can carry it through.
      # @param [Integer] features the value of PSTT_GLOBAL_TX_FEATURES.
      # @raise [Tapyrus::PSTT::Error] if it is not positive.
      def validate_features!(features)
        raise Error, "PSTT_GLOBAL_TX_FEATURES must be greater than 0, but #{features}." unless features.positive?
      end

      # Check that +flags+ sets no reserved bit of PSTT_GLOBAL_TX_MODIFIABLE.
      # @param [Integer] flags the bitfield.
      # @raise [Tapyrus::PSTT::Error] if a reserved bit is set.
      def validate_tx_modifiable!(flags)
        unless (flags & ~TxModifiable::ALL).zero?
          raise Error, "The reserved bits of PSTT_GLOBAL_TX_MODIFIABLE must be 0."
        end
      end

      # Check that +version+ is a version this implementation supports.
      # @param [Integer] version the value of PSTT_GLOBAL_VERSION.
      # @raise [Tapyrus::PSTT::Error] if it is greater than the version TIP-0174 defines.
      def validate_version!(version)
        raise Error, "PSTT version #{version} is not supported." if version > VERSION
      end

      # Check that +value+ is a valid PSTT_IN_REQUIRED_TIME_LOCKTIME.
      # @raise [Tapyrus::PSTT::Error] if it is below the threshold.
      def validate_time_locktime!(value)
        if value < LOCKTIME_THRESHOLD
          raise Error, "PSTT_IN_REQUIRED_TIME_LOCKTIME must be greater than or equal to #{LOCKTIME_THRESHOLD}."
        end
      end

      # Check that +value+ is a valid PSTT_IN_REQUIRED_HEIGHT_LOCKTIME.
      # @raise [Tapyrus::PSTT::Error] if it is out of range.
      def validate_height_locktime!(value)
        if value.zero? || value >= LOCKTIME_THRESHOLD
          raise Error, "PSTT_IN_REQUIRED_HEIGHT_LOCKTIME must be greater than 0 and less than #{LOCKTIME_THRESHOLD}."
        end
      end
    end
  end
end
