module Tapyrus
  module PSTT
    # An input map of a PSTT.
    class Input
      # @!attribute [rw] out_point
      #   @return [Tapyrus::OutPoint] PSTT_IN_PREVIOUS_TXID and PSTT_IN_OUTPUT_INDEX.
      attr_accessor :out_point

      # @!attribute [rw] utxo
      #   @return [Tapyrus::Tx] the complete previous transaction which contains the output being spent.
      attr_accessor :utxo

      # @!attribute [rw] sighash_type
      #   @return [Integer] the sighash type signers must use for this input.
      attr_accessor :sighash_type

      # @!attribute [rw] redeem_script
      #   @return [Tapyrus::Script] the redeem script, if the output being spent is P2SH or CP2SH.
      attr_accessor :redeem_script

      # @!attribute [rw] final_script_sig
      #   @return [Tapyrus::Script] the complete scriptSig for this input.
      attr_accessor :final_script_sig

      # @!attribute [rw] sequence
      #   @return [Integer] the sequence number. nil means the default 0xFFFFFFFF.
      attr_accessor :sequence

      # @!attribute [rw] required_time_locktime
      #   @return [Integer] the minimum Unix timestamp the transaction's locktime must be.
      attr_accessor :required_time_locktime

      # @!attribute [rw] required_height_locktime
      #   @return [Integer] the minimum block height the transaction's locktime must be.
      attr_accessor :required_height_locktime

      # @!attribute [r] partial_sigs
      #   @return [Hash] the signatures for this input, keyed by public key with hex format.
      attr_reader :partial_sigs

      # @!attribute [r] bip32_derivations
      #   @return [Hash] Tapyrus::PSTT::KeyOriginInfo, keyed by public key with hex format.
      attr_reader :bip32_derivations

      # @!attribute [r] ripemd160_preimages
      #   @return [Hash] the preimages, keyed by hash with hex format.
      attr_reader :ripemd160_preimages

      # @!attribute [r] sha256_preimages
      #   @return [Hash] the preimages, keyed by hash with hex format.
      attr_reader :sha256_preimages

      # @!attribute [r] hash160_preimages
      #   @return [Hash] the preimages, keyed by hash with hex format.
      attr_reader :hash160_preimages

      # @!attribute [r] hash256_preimages
      #   @return [Hash] the preimages, keyed by hash with hex format.
      attr_reader :hash256_preimages

      # @!attribute [r] proprietaries
      #   @return [Array[Tapyrus::PSTT::Proprietary]] the proprietary records.
      attr_reader :proprietaries

      # @!attribute [r] unknowns
      #   @return [Hash] the records whose key type this implementation does not know, keyed by complete key.
      attr_reader :unknowns

      # @!attribute [rw] record_order
      #   @return [Array[String]] the complete keys of the map this input was parsed from. See
      #     Tapyrus::PSTT.order_records.
      attr_accessor :record_order

      # @param [Tapyrus::OutPoint] out_point the output being spent.
      def initialize(out_point: nil, utxo: nil, sequence: nil)
        @out_point = out_point
        @utxo = utxo
        @sequence = sequence
        @partial_sigs = {}
        @bip32_derivations = {}
        @ripemd160_preimages = {}
        @sha256_preimages = {}
        @hash160_preimages = {}
        @hash256_preimages = {}
        @proprietaries = []
        @unknowns = {}
        @record_order = []
      end

      # Build an input map from the records of an input map.
      # @param [Array[Tapyrus::PSTT::KeyValue]] records the records.
      # @return [Tapyrus::PSTT::Input]
      # @raise [Tapyrus::PSTT::Error] if a required field is missing or a field is malformed.
      def self.parse_from_records(records)
        input = new
        txid = nil
        index = nil
        records.each do |record|
          if InputTypes::RESERVED.include?(record.type)
            raise Error, format("Input key type 0x%02x is reserved.", record.type)
          end
          case record.type
          when InputTypes::UTXO
            PSTT.validate_empty_keydata!(record)
            input.utxo = parse_utxo(record.value)
          when InputTypes::PARTIAL_SIG
            PSTT.validate_pubkey_keydata!(record)
            if record.value.empty?
              raise Error, "PSTT_IN_PARTIAL_SIG must carry a signature followed by the 1-byte sighash type."
            end
            input.partial_sigs[record.keydata.bth] = record.value
          when InputTypes::SIGHASH_TYPE
            PSTT.validate_empty_keydata!(record)
            input.sighash_type = PSTT.read_u32(record)
            PSTT.validate_sighash_type!(input.sighash_type)
          when InputTypes::REDEEM_SCRIPT
            PSTT.validate_empty_keydata!(record)
            input.redeem_script =
              PSTT.parse_field("PSTT_IN_REDEEM_SCRIPT") { Tapyrus::Script.parse_from_payload(record.value) }
          when InputTypes::BIP32_DERIVATION
            PSTT.validate_pubkey_keydata!(record)
            input.bip32_derivations[record.keydata.bth] = KeyOriginInfo.parse_from_payload(record.value)
          when InputTypes::FINAL_SCRIPTSIG
            PSTT.validate_empty_keydata!(record)
            input.final_script_sig =
              PSTT.parse_field("PSTT_IN_FINAL_SCRIPTSIG") { Tapyrus::Script.parse_from_payload(record.value) }
          when InputTypes::RIPEMD160, InputTypes::HASH160
            raise Error, "The preimage hash must be 20 bytes." unless record.keydata.bytesize == 20
            input.preimages_for(record.type)[record.keydata.bth] = record.value
          when InputTypes::SHA256, InputTypes::HASH256
            raise Error, "The preimage hash must be 32 bytes." unless record.keydata.bytesize == 32
            input.preimages_for(record.type)[record.keydata.bth] = record.value
          when InputTypes::PREVIOUS_TXID
            PSTT.validate_empty_keydata!(record)
            PSTT.validate_value_size!(record, 32)
            txid = record.value.bth
          when InputTypes::OUTPUT_INDEX
            PSTT.validate_empty_keydata!(record)
            index = PSTT.read_u32(record)
          when InputTypes::SEQUENCE
            PSTT.validate_empty_keydata!(record)
            input.sequence = PSTT.read_u32(record)
          when InputTypes::REQUIRED_TIME_LOCKTIME
            PSTT.validate_empty_keydata!(record)
            input.required_time_locktime = PSTT.read_u32(record)
            PSTT.validate_time_locktime!(input.required_time_locktime)
          when InputTypes::REQUIRED_HEIGHT_LOCKTIME
            PSTT.validate_empty_keydata!(record)
            input.required_height_locktime = PSTT.read_u32(record)
            PSTT.validate_height_locktime!(input.required_height_locktime)
          when InputTypes::PROPRIETARY
            input.proprietaries << Proprietary.parse_from_record(record)
          else
            input.unknowns[record.key] = record.value
          end
        end
        raise Error, "PSTT_IN_PREVIOUS_TXID is required." unless txid
        raise Error, "PSTT_IN_OUTPUT_INDEX is required." unless index
        input.out_point = Tapyrus::OutPoint.new(txid, index)
        input.record_order = records.map(&:key)
        input.validate_sighash_type!
        input
      end

      # Parse the value of a PSTT_IN_UTXO record.
      # @param [String] payload the complete previous transaction with binary format.
      # @return [Tapyrus::Tx]
      # @raise [Tapyrus::PSTT::Error] if the value is not exactly one Tapyrus transaction.
      def self.parse_utxo(payload)
        utxo = PSTT.parse_field("PSTT_IN_UTXO") { Tapyrus::Tx.parse_from_payload(payload) }
        # Tapyrus::Tx.parse_from_payload ignores trailing bytes. They would be lost when this
        # input is serialized again, which a Combiner must not do.
        raise Error, "PSTT_IN_UTXO has trailing bytes after the transaction." unless utxo.to_payload == payload
        utxo
      end
      private_class_method :parse_utxo

      # @return [Array[Tapyrus::PSTT::KeyValue]] the records of this input map.
      def to_records
        validate_sighash_type!
        records = []
        records << KeyValue.new(InputTypes::UTXO, "".b, utxo.to_payload) if utxo
        partial_sigs.each { |pubkey, sig| records << KeyValue.new(InputTypes::PARTIAL_SIG, pubkey.htb, sig) }
        records << KeyValue.new(InputTypes::SIGHASH_TYPE, "".b, [sighash_type].pack("V")) if sighash_type
        records << KeyValue.new(InputTypes::REDEEM_SCRIPT, "".b, redeem_script.to_payload) if redeem_script
        bip32_derivations.each do |pubkey, info|
          records << KeyValue.new(InputTypes::BIP32_DERIVATION, pubkey.htb, info.to_payload)
        end
        records << KeyValue.new(InputTypes::FINAL_SCRIPTSIG, "".b, final_script_sig.to_payload) if final_script_sig
        {
          InputTypes::RIPEMD160 => ripemd160_preimages,
          InputTypes::SHA256 => sha256_preimages,
          InputTypes::HASH160 => hash160_preimages,
          InputTypes::HASH256 => hash256_preimages
        }.each { |type, preimages| preimages.each { |hash, image| records << KeyValue.new(type, hash.htb, image) } }
        raise Error, "PSTT_IN_PREVIOUS_TXID is required." unless out_point
        records << KeyValue.new(InputTypes::PREVIOUS_TXID, "".b, out_point.tx_hash.htb)
        records << KeyValue.new(InputTypes::OUTPUT_INDEX, "".b, [out_point.index].pack("V"))
        records << KeyValue.new(InputTypes::SEQUENCE, "".b, [sequence].pack("V")) if sequence
        if required_time_locktime
          PSTT.validate_time_locktime!(required_time_locktime)
          records << KeyValue.new(InputTypes::REQUIRED_TIME_LOCKTIME, "".b, [required_time_locktime].pack("V"))
        end
        if required_height_locktime
          PSTT.validate_height_locktime!(required_height_locktime)
          records << KeyValue.new(InputTypes::REQUIRED_HEIGHT_LOCKTIME, "".b, [required_height_locktime].pack("V"))
        end
        proprietaries.each { |p| records << p.to_record(InputTypes::PROPRIETARY) }
        unknowns.each { |key, value| records << unknown_record(key, value) }
        records
      end

      def to_payload
        PSTT.serialize_map(to_records, record_order)
      end

      # @return [Integer] the sequence number used in the transaction.
      def final_sequence
        sequence || Tapyrus::TxIn::SEQUENCE_FINAL
      end

      # @return [Tapyrus::TxOut] the output being spent, or nil if PSTT_IN_UTXO is absent.
      def utxo_output
        return nil unless utxo
        utxo.outputs[out_point.index]
      end

      # @return [Boolean] whether this input has at least one signature.
      def signed?
        !partial_sigs.empty?
      end

      # @return [Boolean] whether this input has been finalized.
      def finalized?
        !final_script_sig.nil?
      end

      # The scriptCode used to compute the signature hash of this input.
      # @return [Tapyrus::Script]
      # @raise [Tapyrus::PSTT::Error] if the scriptCode cannot be determined.
      def script_code
        script = spent_script_pubkey
        return script unless script.p2sh? || script.cp2sh?
        raise Error, "PSTT_IN_REDEEM_SCRIPT is required to spend a P2SH or CP2SH output." unless redeem_script
        validate_redeem_script!
        redeem_script
      end

      # The scriptPubKey of the output being spent.
      # @return [Tapyrus::Script]
      # @raise [Tapyrus::PSTT::Error] if PSTT_IN_UTXO is absent or does not contain the output.
      def spent_script_pubkey
        validate_utxo!
        utxo_output.script_pubkey
      end

      # Check that PSTT_IN_UTXO is present and identifies the output being spent.
      # @raise [Tapyrus::PSTT::Error] if it is not.
      def validate_utxo!
        raise Error, "PSTT_IN_UTXO is required." unless utxo
        raise Error, "The txid of PSTT_IN_UTXO does not match PSTT_IN_PREVIOUS_TXID." unless utxo.txid == out_point.txid
        raise Error, "PSTT_IN_OUTPUT_INDEX does not exist in PSTT_IN_UTXO." unless utxo.outputs[out_point.index]
      end

      # Check that the redeem script hashes to the value committed in the scriptPubKey being spent.
      # @raise [Tapyrus::PSTT::Error] if it does not.
      def validate_redeem_script!
        return unless redeem_script
        script = spent_script_pubkey
        committed =
          if script.p2sh?
            script.chunks[1].pushed_data
          elsif script.cp2sh?
            script.chunks[3].pushed_data
          else
            raise Error, "PSTT_IN_REDEEM_SCRIPT is set but the output being spent is neither P2SH nor CP2SH."
          end
        unless redeem_script.to_hash160 == committed.bth
          raise Error, "PSTT_IN_REDEEM_SCRIPT does not hash to the value committed in the scriptPubKey."
        end
      end

      # Check that this input requests a sighash type TIP-0174 defines, and that every signature
      # it carries uses it. TIP-0174 obliges a Signer to use PSTT_IN_SIGHASH_TYPE, so an input
      # which carries a signature made with another type contradicts itself: the signature covers
      # a different transaction than the input asks for.
      # @raise [Tapyrus::PSTT::Error] if a signature uses another sighash type.
      def validate_sighash_type!
        return unless sighash_type
        PSTT.validate_sighash_type!(sighash_type)
        partial_sigs.each do |pubkey, sig|
          next if sig.empty?
          hash_type = sig[-1].unpack1("C")
          next if hash_type == sighash_type
          raise Error,
                format(
                  "PSTT_IN_PARTIAL_SIG for %s uses sighash type 0x%x, but PSTT_IN_SIGHASH_TYPE requires 0x%x.",
                  pubkey,
                  hash_type,
                  sighash_type
                )
        end
      end

      # Check everything a Signer must verify before signing this input.
      # @raise [Tapyrus::PSTT::Error] if a check fails.
      def validate_for_sign!
        validate_utxo!
        validate_redeem_script!
        validate_sighash_type!
      end

      # Check that +algo+ does not conflict with the scheme of the signatures already collected.
      # Tapyrus does not allow mixing ECDSA and Schnorr signatures within a single OP_CHECKMULTISIG.
      # @param [Symbol] algo :ecdsa or :schnorr.
      # @raise [Tapyrus::PSTT::Error] if the schemes conflict.
      def validate_signature_algo!(algo)
        return if partial_sigs.empty?
        current = partial_sigs.values.first.bytesize == 65 ? :schnorr : :ecdsa
        unless current == algo
          raise Error, "This input already has #{current} signatures. #{algo} signatures must not be mixed."
        end
      end

      # Whether the given signature commits to the sequence number of every input.
      # A SIGHASH_ALL signature without SIGHASH_ANYONECANPAY does.
      # @param [String] sig a signature with binary format.
      # @return [Boolean]
      def self.commits_to_all_sequences?(sig)
        return false if sig.nil? || sig.empty?
        hash_type = sig[-1].unpack1("C")
        (hash_type & SIGHASH_TYPE[:anyonecanpay]).zero? && (hash_type & 0x1f) == SIGHASH_TYPE[:all]
      end

      # Assemble the complete scriptSig from the collected records and store it in PSTT_IN_FINAL_SCRIPTSIG.
      # The records which are no longer needed are removed.
      # @param [Hash] verified_sigs the signatures which verify against the transaction, keyed by
      #   public key with hex format. Deciding that needs the whole transaction, which an input
      #   map does not hold, so Tapyrus::PSTT::Tx#finalize! computes it and passes it here.
      # @return [Tapyrus::PSTT::Input] self.
      # @raise [Tapyrus::PSTT::Error] if the verified signatures do not satisfy the script being spent.
      def finalize!(verified_sigs)
        return self if finalized?
        validate_for_sign!
        self.final_script_sig = build_final_script_sig(verified_sigs)
        partial_sigs.clear
        bip32_derivations.clear
        ripemd160_preimages.clear
        sha256_preimages.clear
        hash160_preimages.clear
        hash256_preimages.clear
        self.sighash_type = nil
        self.redeem_script = nil
        self
      end

      # @param [Integer] type a preimage key type.
      # @return [Hash] the preimages of the type.
      def preimages_for(type)
        case type
        when InputTypes::RIPEMD160
          ripemd160_preimages
        when InputTypes::SHA256
          sha256_preimages
        when InputTypes::HASH160
          hash160_preimages
        when InputTypes::HASH256
          hash256_preimages
        end
      end

      def ==(other)
        other.is_a?(Input) && to_payload == other.to_payload
      end

      private

      def unknown_record(key, value)
        buf = StringIO.new(key)
        type = PSTT.read_compact_size(buf)
        KeyValue.new(type, buf.read || "".b, value)
      end

      # Build the complete scriptSig for the script being spent.
      def build_final_script_sig(verified_sigs)
        script = spent_script_pubkey
        p2sh = script.p2sh? || script.cp2sh?
        target = p2sh ? redeem_script : script
        raise Error, "PSTT_IN_REDEEM_SCRIPT is required to finalize a P2SH or CP2SH input." if p2sh && !target
        script_sig =
          if target.p2pkh? || target.cp2pkh?
            build_p2pkh_script_sig(target, verified_sigs)
          elsif target.multisig?
            build_multisig_script_sig(target, verified_sigs)
          else
            raise Error, "Unsupported script type. The scriptSig must be assembled by the application."
          end
        script_sig << redeem_script.to_payload if p2sh
        script_sig
      end

      def build_p2pkh_script_sig(target, verified_sigs)
        pubkey_hash = target.chunks[target.cp2pkh? ? 4 : 2].pushed_data.bth
        pubkey, sig = verified_sigs.find { |key, _| Tapyrus.hash160(key) == pubkey_hash }
        raise Error, "No valid signature for the public key committed in the scriptPubKey." unless sig
        Tapyrus::Script.new << sig << pubkey.htb
      end

      def build_multisig_script_sig(target, verified_sigs)
        threshold = Tapyrus::Opcodes.opcode_to_small_int(target.chunks[0].opcode)
        sigs = target.get_multisig_pubkeys.map { |pubkey| verified_sigs[pubkey.bth] }.compact
        if sigs.size < threshold
          raise Error, "#{threshold} signatures are required, but only #{sigs.size} of the collected ones are valid."
        end
        # OP_0 is the dummy element OP_CHECKMULTISIG pops off the stack.
        script_sig = Tapyrus::Script.new << Tapyrus::Opcodes::OP_0
        sigs.take(threshold).each { |sig| script_sig << sig }
        script_sig
      end
    end
  end
end
