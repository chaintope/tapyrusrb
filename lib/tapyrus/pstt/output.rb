module Tapyrus
  module PSTT
    # An output map of a PSTT.
    class Output
      # @!attribute [rw] amount
      #   @return [Integer] the amount of this output. Tokens for a colored output, otherwise tapy.
      attr_accessor :amount

      # @!attribute [rw] script_pubkey
      #   @return [Tapyrus::Script] the scriptPubKey of this output.
      attr_accessor :script_pubkey

      # @!attribute [rw] redeem_script
      #   @return [Tapyrus::Script] the redeem script, if this output is P2SH or CP2SH.
      attr_accessor :redeem_script

      # @!attribute [r] bip32_derivations
      #   @return [Hash] Tapyrus::PSTT::KeyOriginInfo, keyed by public key with hex format.
      attr_reader :bip32_derivations

      # @!attribute [r] proprietaries
      #   @return [Array[Tapyrus::PSTT::Proprietary]] the proprietary records.
      attr_reader :proprietaries

      # @!attribute [r] unknowns
      #   @return [Hash] the records whose key type this implementation does not know, keyed by complete key.
      attr_reader :unknowns

      # @!attribute [rw] record_order
      #   @return [Array[String]] the complete keys of the map this output was parsed from. See
      #     Tapyrus::PSTT.order_records.
      attr_accessor :record_order

      def initialize(amount: nil, script_pubkey: nil, redeem_script: nil)
        @amount = amount
        @script_pubkey = script_pubkey
        @redeem_script = redeem_script
        @bip32_derivations = {}
        @proprietaries = []
        @unknowns = {}
        @record_order = []
      end

      # Build an output map from the records of an output map.
      # @param [Array[Tapyrus::PSTT::KeyValue]] records the records.
      # @return [Tapyrus::PSTT::Output]
      # @raise [Tapyrus::PSTT::Error] if a required field is missing or a field is malformed.
      def self.parse_from_records(records)
        output = new
        records.each do |record|
          if OutputTypes::RESERVED.include?(record.type)
            raise Error, format("Output key type 0x%02x is reserved.", record.type)
          end
          case record.type
          when OutputTypes::REDEEM_SCRIPT
            PSTT.validate_empty_keydata!(record)
            output.redeem_script =
              PSTT.parse_field("PSTT_OUT_REDEEM_SCRIPT") { Tapyrus::Script.parse_from_payload(record.value) }
          when OutputTypes::BIP32_DERIVATION
            PSTT.validate_pubkey_keydata!(record)
            output.bip32_derivations[record.keydata.bth] = KeyOriginInfo.parse_from_payload(record.value)
          when OutputTypes::AMOUNT
            PSTT.validate_empty_keydata!(record)
            output.amount = PSTT.read_i64(record)
            PSTT.validate_amount!(output.amount)
          when OutputTypes::SCRIPT
            PSTT.validate_empty_keydata!(record)
            output.script_pubkey =
              PSTT.parse_field("PSTT_OUT_SCRIPT") { Tapyrus::Script.parse_from_payload(record.value) }
          when OutputTypes::PROPRIETARY
            output.proprietaries << Proprietary.parse_from_record(record)
          else
            output.unknowns[record.key] = record.value
          end
        end
        raise Error, "PSTT_OUT_AMOUNT is required." unless output.amount
        raise Error, "PSTT_OUT_SCRIPT is required." unless output.script_pubkey
        output.record_order = records.map(&:key)
        output
      end

      # @return [Array[Tapyrus::PSTT::KeyValue]] the records of this output map.
      def to_records
        raise Error, "PSTT_OUT_AMOUNT is required." unless amount
        raise Error, "PSTT_OUT_SCRIPT is required." unless script_pubkey
        PSTT.validate_amount!(amount)
        records = []
        records << KeyValue.new(OutputTypes::REDEEM_SCRIPT, "".b, redeem_script.to_payload) if redeem_script
        bip32_derivations.each do |pubkey, info|
          records << KeyValue.new(OutputTypes::BIP32_DERIVATION, pubkey.htb, info.to_payload)
        end
        records << KeyValue.new(OutputTypes::AMOUNT, "".b, [amount].pack("q<"))
        records << KeyValue.new(OutputTypes::SCRIPT, "".b, script_pubkey.to_payload)
        proprietaries.each { |p| records << p.to_record(OutputTypes::PROPRIETARY) }
        unknowns.each do |key, value|
          buf = StringIO.new(key)
          type = PSTT.read_compact_size(buf)
          records << KeyValue.new(type, buf.read || "".b, value)
        end
        records
      end

      def to_payload
        PSTT.serialize_map(to_records, record_order)
      end

      # @return [Tapyrus::TxOut] the transaction output this map represents.
      # @raise [Tapyrus::PSTT::Error] if the amount is out of range.
      def to_tx_out
        PSTT.validate_amount!(amount)
        Tapyrus::TxOut.new(value: amount, script_pubkey: script_pubkey)
      end

      # @return [Boolean] whether this output holds Colored Coins.
      def colored?
        script_pubkey.colored?
      end

      # @return [Tapyrus::Color::ColorIdentifier] the color of this output, or nil for TPC.
      def color_id
        script_pubkey.color_id
      end

      def ==(other)
        other.is_a?(Output) && to_payload == other.to_payload
      end
    end
  end
end
