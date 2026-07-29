module Tapyrus
  module PSTT
    # A Partially Signed Tapyrus Transaction.
    #
    # The methods are grouped by the roles TIP-0174 defines: Creator(::new), Constructor(#add_input,
    # #add_output, #add_pair, #finish_construction!), Updater(#update_input, #set_sequence),
    # Signer(#sign), Combiner(#combine), Input Finalizer(#finalize!) and
    # Transaction Extractor(#extract_tx).
    class Tx
      include Tapyrus::HexConverter

      # @!attribute [r] features
      #   @return [Integer] the features field of the transaction. Tapyrus currently defines only 1.
      attr_reader :features

      # @!attribute [r] fallback_locktime
      #   @return [Integer] the locktime to use if no input specifies a required locktime.
      attr_reader :fallback_locktime

      # @!attribute [r] tx_modifiable
      #   @return [Integer] the bitfield of PSTT_GLOBAL_TX_MODIFIABLE. nil means not modifiable.
      attr_reader :tx_modifiable

      # @!attribute [rw] version
      #   @return [Integer] the version number of this PSTT.
      attr_accessor :version

      # @!attribute [r] inputs
      #   @return [Array[Tapyrus::PSTT::Input]] the input maps.
      attr_reader :inputs

      # @!attribute [r] outputs
      #   @return [Array[Tapyrus::PSTT::Output]] the output maps.
      attr_reader :outputs

      # @!attribute [r] xpubs
      #   @return [Hash] Tapyrus::PSTT::KeyOriginInfo, keyed by the Base58 extended public key.
      attr_reader :xpubs

      # @!attribute [r] proprietaries
      #   @return [Array[Tapyrus::PSTT::Proprietary]] the proprietary records.
      attr_reader :proprietaries

      # @!attribute [r] unknowns
      #   @return [Hash] the records whose key type this implementation does not know, keyed by complete key.
      attr_reader :unknowns

      # @!attribute [rw] global_record_order
      #   @return [Array[String]] the complete keys of the global map this PSTT was parsed from.
      #     See Tapyrus::PSTT.order_records.
      attr_accessor :global_record_order

      # Create a new PSTT. This is the Creator role.
      # @param [Integer] features the features field of the transaction.
      # @param [Integer] tx_modifiable the initial value of PSTT_GLOBAL_TX_MODIFIABLE.
      #   Set Tapyrus::PSTT::TxModifiable::INPUTS and/or OUTPUTS if other parties will add
      #   inputs or outputs. nil fixes the transaction at creation.
      # @param [Array[Tapyrus::PSTT::Input]] inputs the inputs the Creator creates.
      # @param [Array[Tapyrus::PSTT::Output]] outputs the outputs the Creator creates.
      def initialize(features: 1, fallback_locktime: nil, tx_modifiable: nil, version: VERSION, inputs: [], outputs: [])
        @features = features
        @fallback_locktime = fallback_locktime
        @tx_modifiable = tx_modifiable
        @version = version
        @inputs = inputs
        @outputs = outputs
        @xpubs = {}
        @proprietaries = []
        @unknowns = {}
        @global_record_order = []
      end

      # Set the features field of the transaction. The signature hash covers it, so it must not
      # change once the PSTT holds a signature.
      # @param [Integer] value the features field.
      # @raise [Tapyrus::PSTT::Error] if the PSTT already contains signatures.
      def features=(value)
        if value != @features && signed?
          raise Error, "The features of a PSTT which already contains signatures must not be changed."
        end
        @features = value
      end

      # Set PSTT_GLOBAL_FALLBACK_LOCKTIME. The signature hash covers the locktime of the
      # transaction, so a change which alters it is refused once the PSTT holds a signature.
      # @param [Integer] value the fallback locktime.
      # @raise [Tapyrus::PSTT::Error] if the change alters the locktime.
      def fallback_locktime=(value)
        return @fallback_locktime = value if value == @fallback_locktime
        previous = @fallback_locktime
        keeping_locktime("PSTT_GLOBAL_FALLBACK_LOCKTIME") do
          @fallback_locktime = value
          -> { @fallback_locktime = previous }
        end
      end

      # Set PSTT_GLOBAL_TX_MODIFIABLE. Once the PSTT holds a signature the field records what
      # those signatures still allow, so it may only be tightened: setting Inputs Modifiable or
      # Outputs Modifiable again would re-open the very modification a Signer closed by signing,
      # and clearing Has SIGHASH_SINGLE would drop the pairing rule which keeps a SIGHASH_SINGLE
      # signature covering its own output.
      # @param [Integer] value the bitfield, or nil to omit the field.
      # @raise [Tapyrus::PSTT::Error] if a reserved bit is set, or the value relaxes the field.
      def tx_modifiable=(value)
        PSTT.validate_tx_modifiable!(value) if value
        validate_tx_modifiable_tightens!(value) if signed?
        @tx_modifiable = value
      end

      # Parse a PSTT from its raw binary format.
      # @param [String] payload a PSTT with binary format.
      # @return [Tapyrus::PSTT::Tx]
      # @raise [Tapyrus::PSTT::Error] if the payload is not a valid PSTT.
      def self.parse_from_payload(payload)
        buf = payload.is_a?(String) ? StringIO.new(payload) : payload
        unless PSTT.read_bytes(buf, MAGIC.bytesize) == MAGIC
          raise Error, "Invalid PSTT magic. The payload does not begin with 'pstt' 0xFF."
        end
        # Every map is read before any of them is interpreted, so that the declared counts are
        # compared against the number of maps which is actually there. Assigning maps to inputs
        # and outputs by the declared counts alone would let a wrong count hand an output map to
        # the input parser, which reports whichever field of the misread map fails first.
        maps = []
        maps << PSTT.parse_map(buf) until buf.eof?
        raise Error, "The PSTT global map is missing." if maps.empty?
        pstt, input_count, output_count = parse_global_map(maps.shift)
        unless maps.size == input_count + output_count
          raise Error, "The number of maps does not match PSTT_GLOBAL_INPUT_COUNT and PSTT_GLOBAL_OUTPUT_COUNT."
        end
        maps.shift(input_count).each { |records| pstt.inputs << Input.parse_from_records(records) }
        maps.each { |records| pstt.outputs << Output.parse_from_records(records) }
        pstt
      end

      # Parse a PSTT from its Base64 format.
      # @param [String] base64 a PSTT with Base64 format.
      # @return [Tapyrus::PSTT::Tx]
      def self.from_base64(base64)
        payload = base64.unpack1("m0")
        raise Error, "Invalid Base64 encoding." if payload.nil?
        parse_from_payload(payload)
      rescue ArgumentError
        raise Error, "Invalid Base64 encoding."
      end

      def to_payload
        MAGIC + PSTT.serialize_map(global_records, global_record_order) + inputs.map(&:to_payload).join +
          outputs.map(&:to_payload).join
      end

      # @return [String] this PSTT with Base64 format, which is used for display and text transport.
      def to_base64
        [to_payload].pack("m0")
      end

      # @return [Array[Tapyrus::PSTT::KeyValue]] the records of the global map.
      def global_records
        raise Error, "PSTT_GLOBAL_TX_FEATURES is required." unless features
        PSTT.validate_tx_modifiable!(tx_modifiable) if tx_modifiable
        PSTT.validate_version!(version) if version
        records = []
        xpubs.each do |xpub, info|
          keydata = PSTT.parse_field("PSTT_GLOBAL_XPUB") { Tapyrus::ExtPubkey.from_base58(xpub).to_payload }
          records << KeyValue.new(GlobalTypes::XPUB, keydata, info.to_payload)
        end
        records << KeyValue.new(GlobalTypes::TX_FEATURES, "".b, [features].pack("l<"))
        if fallback_locktime
          records << KeyValue.new(GlobalTypes::FALLBACK_LOCKTIME, "".b, [fallback_locktime].pack("V"))
        end
        records << KeyValue.new(GlobalTypes::INPUT_COUNT, "".b, Tapyrus.pack_var_int(inputs.size))
        records << KeyValue.new(GlobalTypes::OUTPUT_COUNT, "".b, Tapyrus.pack_var_int(outputs.size))
        records << KeyValue.new(GlobalTypes::TX_MODIFIABLE, "".b, [tx_modifiable].pack("C")) if tx_modifiable
        records << KeyValue.new(GlobalTypes::VERSION, "".b, [version].pack("V")) if version && version > 0
        proprietaries.each { |p| records << p.to_record(GlobalTypes::PROPRIETARY) }
        unknowns.each do |key, value|
          buf = StringIO.new(key)
          type = PSTT.read_compact_size(buf)
          records << KeyValue.new(type, buf.read || "".b, value)
        end
        records
      end

      # The locktime of the transaction, computed as Determining the Locktime describes.
      # @return [Integer] the locktime.
      # @raise [Tapyrus::PSTT::Error] if no locktime kind is acceptable to every input.
      def locktime
        time_locktimes = []
        height_locktimes = []
        only_time = false
        only_height = false
        inputs.each do |input|
          time = input.required_time_locktime
          height = input.required_height_locktime
          next unless time || height
          time_locktimes << time if time
          height_locktimes << height if height
          only_time = true if time && !height
          only_height = true if height && !time
        end
        return fallback_locktime || 0 if time_locktimes.empty? && height_locktimes.empty?
        if only_time && only_height
          raise Error, "No locktime kind is acceptable to every input which requires a locktime."
        end
        # If both kinds are acceptable, the height-based locktime is chosen.
        only_time ? time_locktimes.max : height_locktimes.max
      end

      # Build the transaction determined by the fields of this PSTT.
      # @param [Integer] sequence override the sequence number of every input.
      # @param [Boolean] final whether to attach PSTT_IN_FINAL_SCRIPTSIG to each input.
      # @return [Tapyrus::Tx]
      def build_tx(sequence: nil, final: false)
        tx = Tapyrus::Tx.new
        tx.features = features
        tx.lock_time = locktime
        inputs.each do |input|
          script_sig = final ? input.final_script_sig : Tapyrus::Script.new
          tx.inputs << Tapyrus::TxIn.new(
            out_point: input.out_point,
            script_sig: script_sig,
            sequence: sequence || input.final_sequence
          )
        end
        outputs.each { |output| tx.outputs << output.to_tx_out }
        tx
      end

      # The identifier of this PSTT: the txid of the transaction built from its fields with the
      # sequence number of every input set to 0.
      # @return [String] the txid with hex format.
      def identification_txid
        build_tx(sequence: 0).txid
      end

      # @return [Boolean] whether inputs may still be added.
      def inputs_modifiable?
        !(tx_modifiable.to_i & TxModifiable::INPUTS).zero?
      end

      # @return [Boolean] whether outputs may still be added.
      def outputs_modifiable?
        !(tx_modifiable.to_i & TxModifiable::OUTPUTS).zero?
      end

      # @return [Boolean] whether this PSTT contains a signature made with SIGHASH_SINGLE.
      def has_sighash_single?
        !(tx_modifiable.to_i & TxModifiable::HAS_SIGHASH_SINGLE).zero?
      end

      # Whether any input carries a signature. A finalized input counts as signed even though its
      # PSTT_IN_PARTIAL_SIG records are gone: its signatures moved into PSTT_IN_FINAL_SCRIPTSIG,
      # where they still commit to everything they committed to before.
      # @return [Boolean]
      def signed?
        inputs.any? { |input| input.signed? || input.finalized? }
      end

      # Add an input. This is the Constructor role.
      # @param [Tapyrus::PSTT::Input] input the input to be added.
      # @return [Tapyrus::PSTT::Tx] self.
      # @raise [Tapyrus::PSTT::Error] if the input must not be added.
      def add_input(input)
        raise Error, "Inputs are not modifiable." unless inputs_modifiable?
        if has_sighash_single?
          raise Error, "This PSTT contains a SIGHASH_SINGLE signature. Use #add_pair to keep inputs and outputs paired."
        end
        keeping_locktime("The added input") do
          inputs << input
          -> { inputs.pop }
        end
        self
      end

      # Add an output. This is the Constructor role.
      # @param [Tapyrus::PSTT::Output] output the output to be added.
      # @return [Tapyrus::PSTT::Tx] self.
      # @raise [Tapyrus::PSTT::Error] if the output must not be added.
      def add_output(output)
        raise Error, "Outputs are not modifiable." unless outputs_modifiable?
        if has_sighash_single?
          raise Error, "This PSTT contains a SIGHASH_SINGLE signature. Use #add_pair to keep inputs and outputs paired."
        end
        outputs << output
        self
      end

      # Add an input and an output at matching positions after the existing ones. A PSTT which
      # contains a SIGHASH_SINGLE signature must preserve that correspondence.
      # @param [Tapyrus::PSTT::Input] input the input to be added.
      # @param [Tapyrus::PSTT::Output] output the output to be added.
      # @return [Tapyrus::PSTT::Tx] self.
      # @raise [Tapyrus::PSTT::Error] if the pair must not be added.
      def add_pair(input, output)
        raise Error, "Inputs are not modifiable." unless inputs_modifiable?
        raise Error, "Outputs are not modifiable." unless outputs_modifiable?
        # Appending never moves an existing input or output, so the only thing to enforce is that
        # the added input has an output at its own position.
        if inputs.size > outputs.size
          raise Error, "The added input would have no corresponding output at a matching position."
        end
        keeping_locktime("The added input") do
          inputs << input
          -> { inputs.pop }
        end
        outputs << output
        self
      end

      # Declare construction finished by clearing the Inputs Modifiable and Outputs Modifiable flags.
      # @return [Tapyrus::PSTT::Tx] self.
      def finish_construction!
        self.tx_modifiable = tx_modifiable.to_i & ~(TxModifiable::INPUTS | TxModifiable::OUTPUTS)
        self
      end

      # Set the sequence number of an input. This is the Updater role.
      # @param [Integer] index the input index.
      # @param [Integer] sequence the sequence number.
      # @return [Tapyrus::PSTT::Tx] self.
      # @raise [Tapyrus::PSTT::Error] if a collected signature commits to the sequence number.
      def set_sequence(index, sequence)
        input = input_at(index)
        if input.signed? || input.finalized?
          raise Error, "Input #{index} is already signed. Its sequence number must not be changed."
        end
        # A finalized input no longer carries the sighash types of the signatures it was built
        # from, so which of them commit to which sequence number can no longer be decided. Any
        # finalized input therefore blocks every sequence change in the PSTT.
        if inputs.any?(&:finalized?)
          raise Error, "A finalized input carries signatures which may commit to the sequence number of every input."
        end
        if inputs.any? { |i| i.partial_sigs.values.any? { |sig| Input.commits_to_all_sequences?(sig) } }
          raise Error, "A SIGHASH_ALL signature commits to the sequence number of every input. It must not be changed."
        end
        input.sequence = sequence
        self
      end

      # The scriptCode used to compute the signature hash of an input.
      # @param [Integer] index the input index.
      # @return [Tapyrus::Script]
      def script_code(index)
        input_at(index).script_code
      end

      # Compute the signature hash of an input.
      # @param [Integer] index the input index.
      # @param [Integer] sighash_type the sighash type. Defaults to PSTT_IN_SIGHASH_TYPE, or SIGHASH_ALL.
      # @return [String] the signature hash with binary format.
      # @raise [Tapyrus::PSTT::Error] if the input must not be signed.
      def sighash_for_input(index, sighash_type: nil)
        input = input_at(index)
        hash_type = resolve_sighash_type(input, sighash_type)
        if (hash_type & 0x1f) == SIGHASH_TYPE[:single] && index >= outputs.size
          raise Error, "SIGHASH_SINGLE must not be used for an input which has no corresponding output."
        end
        input.validate_for_sign!
        build_tx.sighash_for_input(index, input.script_code, hash_type: hash_type)
      end

      # Sign an input. This is the Signer role.
      # @param [Integer] index the input index.
      # @param [Tapyrus::Key] key the key to sign with.
      # @param [Integer] sighash_type the sighash type. Defaults to PSTT_IN_SIGHASH_TYPE, or SIGHASH_ALL.
      # @param [Symbol] algo the signature scheme. :ecdsa or :schnorr.
      # @param [Boolean] low_r whether to apply low-R grinding to an ECDSA signature.
      # @return [String] the signature which was added, with binary format.
      # @raise [Tapyrus::PSTT::Error] if the input must not be signed.
      def sign(index, key, sighash_type: nil, algo: :ecdsa, low_r: true)
        input = input_at(index)
        # The Input Finalizer removed the PSTT_IN_PARTIAL_SIG records of this input, so a
        # signature added now would recreate a record the format says is no longer there.
        raise Error, "Input #{index} is finalized. It takes no further signature." if input.finalized?
        hash_type = resolve_sighash_type(input, sighash_type)
        input.validate_signature_algo!(algo)
        sighash = sighash_for_input(index, sighash_type: hash_type)
        sig = key.sign(sighash, low_r, nil, algo: algo) + [hash_type].pack("C")
        input.partial_sigs[key.pubkey] = sig
        update_tx_modifiable_after_sign(hash_type)
        sig
      end

      # Merge another PSTT which has the same identifier into this one. This is the Combiner role.
      # @param [Tapyrus::PSTT::Tx] other the PSTT to be merged.
      # @return [Tapyrus::PSTT::Tx] the merged PSTT.
      # @raise [Tapyrus::PSTT::Error] if the identifiers differ.
      def combine(other)
        unless identification_txid == other.identification_txid
          raise Error, "PSTTs with different identifiers must not be combined."
        end
        validate_sequences_agree!(other)
        modifiable = merge_tx_modifiable(tx_modifiable, other.tx_modifiable)
        payload =
          MAGIC + PSTT.serialize_map(merge_records(global_records, other.global_records), global_record_order) +
            inputs
              .zip(other.inputs)
              .map { |a, b| PSTT.serialize_map(merge_records(a.to_records, b.to_records), a.record_order) }
              .join +
            outputs
              .zip(other.outputs)
              .map { |a, b| PSTT.serialize_map(merge_records(a.to_records, b.to_records), a.record_order) }
              .join
        combined = self.class.parse_from_payload(payload)
        combined.tx_modifiable = modifiable
        combined
      end

      # Assemble the complete scriptSig of every input. This is the Input Finalizer role.
      # @return [Tapyrus::PSTT::Tx] self.
      # @raise [Tapyrus::PSTT::Error] if the PSTT is still modifiable, or an input cannot be finalized.
      def finalize!
        raise Error, "This PSTT has no inputs to finalize." if inputs.empty?
        if inputs_modifiable? || outputs_modifiable?
          raise Error, "A PSTT must not be finalized while it is still modifiable."
        end
        inputs.each_with_index { |input, index| input.finalize!(verified_partial_sigs(index)) }
        self
      end

      # The signatures of an input which verify against the transaction this PSTT describes.
      #
      # TIP-0174 has the Input Finalizer check that the collected records are sufficient to
      # satisfy the script of the output being spent, and a signature which does not verify is
      # not. It also matters which ones are dropped: the multisig scriptSig takes the first
      # +threshold+ public keys of the redeem script which carry a signature, so one bad
      # signature among otherwise good ones would displace a good one and yield a scriptSig
      # which fails validation, with the signatures needed to spend the output sitting unused in
      # the same input.
      # @param [Integer] index the input index.
      # @return [Hash] the signatures which verify, keyed by public key with hex format.
      def verified_partial_sigs(index)
        input = input_at(index)
        return {} if input.partial_sigs.empty?
        script_code = input.script_code
        tx = build_tx
        input.partial_sigs.select { |pubkey, sig| verified_sig?(tx, index, script_code, pubkey, sig) }
      end

      # @return [Boolean] whether every input has been finalized.
      def finalized?
        !inputs.empty? && inputs.all?(&:finalized?)
      end

      # Build the final transaction. This is the Transaction Extractor role.
      # @return [Tapyrus::Tx] the transaction in Tapyrus network serialization.
      # @raise [Tapyrus::PSTT::Error] if an input has no PSTT_IN_FINAL_SCRIPTSIG.
      def extract_tx
        raise Error, "This PSTT has no inputs. A transaction must spend at least one output." if inputs.empty?
        inputs.each_with_index do |input, index|
          raise Error, "PSTT_IN_FINAL_SCRIPTSIG for input #{index} is missing." unless input.finalized?
        end
        build_tx(final: true)
      end

      # The amounts being spent, per color. Requires PSTT_IN_UTXO on every input.
      # @return [Hash] Tapyrus::Color::ColorIdentifier => amount. TPC uses the default color identifier.
      def input_amounts
        inputs.each_with_object(Hash.new(0)) do |input, totals|
          input.validate_utxo!
          out = input.utxo_output
          totals[out.color_id || Tapyrus::Color::ColorIdentifier.default] += out.value
        end
      end

      # The amounts being created, per color.
      # @return [Hash] Tapyrus::Color::ColorIdentifier => amount. TPC uses the default color identifier.
      def output_amounts
        outputs.each_with_object(Hash.new(0)) do |output, totals|
          totals[output.color_id || Tapyrus::Color::ColorIdentifier.default] += output.amount
        end
      end

      # The TPC fee this transaction pays. Requires PSTT_IN_UTXO on every input.
      # @return [Integer] the fee in tapy.
      def fee
        tpc = Tapyrus::Color::ColorIdentifier.default
        input_amounts[tpc] - output_amounts[tpc]
      end

      def ==(other)
        other.is_a?(Tx) && to_payload == other.to_payload
      end

      private

      # Build a PSTT from the records of the global map.
      # @return [Array] the PSTT, the declared input count and the declared output count.
      def self.parse_global_map(records)
        pstt = new(features: nil)
        input_count = nil
        output_count = nil
        records.each do |record|
          case record.type
          when GlobalTypes::UNSIGNED_TX
            raise Error, "Global key type 0x00 is reserved."
          when GlobalTypes::XPUB
            unless record.keydata.bytesize == 78
              raise Error, "PSTT_GLOBAL_XPUB keydata must be a 78-byte serialized extended public key."
            end
            xpub = PSTT.parse_field("PSTT_GLOBAL_XPUB") { Tapyrus::ExtPubkey.parse_from_payload(record.keydata) }
            # This PSTT holds the key by its Base58 form, so an extended public key which does not
            # survive that conversion would be re-serialized as different bytes.
            unless xpub.to_payload == record.keydata
              raise Error, "PSTT_GLOBAL_XPUB is not a canonical serialized extended public key."
            end
            pstt.xpubs[xpub.to_base58] = KeyOriginInfo.parse_from_payload(record.value)
          when GlobalTypes::TX_FEATURES
            PSTT.validate_empty_keydata!(record)
            pstt.features = PSTT.read_i32(record)
            PSTT.validate_features!(pstt.features)
          when GlobalTypes::FALLBACK_LOCKTIME
            PSTT.validate_empty_keydata!(record)
            pstt.fallback_locktime = PSTT.read_u32(record)
          when GlobalTypes::INPUT_COUNT
            PSTT.validate_empty_keydata!(record)
            input_count = PSTT.read_count(record)
          when GlobalTypes::OUTPUT_COUNT
            PSTT.validate_empty_keydata!(record)
            output_count = PSTT.read_count(record)
          when GlobalTypes::TX_MODIFIABLE
            PSTT.validate_empty_keydata!(record)
            pstt.tx_modifiable = PSTT.read_u8(record)
          when GlobalTypes::VERSION
            PSTT.validate_empty_keydata!(record)
            pstt.version = PSTT.read_u32(record)
            PSTT.validate_version!(pstt.version)
          when GlobalTypes::PROPRIETARY
            pstt.proprietaries << Proprietary.parse_from_record(record)
          else
            pstt.unknowns[record.key] = record.value
          end
        end
        raise Error, "PSTT_GLOBAL_TX_FEATURES is required." unless pstt.features
        raise Error, "PSTT_GLOBAL_INPUT_COUNT is required." unless input_count
        raise Error, "PSTT_GLOBAL_OUTPUT_COUNT is required." unless output_count
        pstt.global_record_order = records.map(&:key)
        [pstt, input_count, output_count]
      end
      private_class_method :parse_global_map

      def input_at(index)
        input = inputs[index]
        raise Error, "Input #{index} does not exist." unless input
        input
      end

      def resolve_sighash_type(input, sighash_type)
        if input.sighash_type && sighash_type && input.sighash_type != sighash_type
          raise Error, "The sighash type of this input is fixed to #{input.sighash_type} by PSTT_IN_SIGHASH_TYPE."
        end
        hash_type = sighash_type || input.sighash_type || SIGHASH_TYPE[:all]
        # Only the low byte of the sighash type is appended to a signature, while the whole value
        # is committed to by the signature hash. A value which does not fit in a byte would
        # therefore produce a signature nobody can verify.
        PSTT.validate_sighash_type!(hash_type)
        hash_type
      end

      # Whether a signature verifies against +tx+ under the scheme its length selects and the
      # sighash type its last byte names. A record which is not a signature at all, such as
      # malformed DER or a public key which is not a point, is not valid either, so the decoders
      # are allowed to fail here rather than to raise.
      def verified_sig?(tx, index, script_code, pubkey, sig)
        hash_type = sig[-1].unpack1("C")
        return false unless SIGHASH_TYPES.include?(hash_type)
        input = inputs[index]
        return false if input.sighash_type && input.sighash_type != hash_type
        return false if (hash_type & 0x1f) == SIGHASH_TYPE[:single] && index >= outputs.size
        sighash = tx.sighash_for_input(index, script_code, hash_type: hash_type)
        algo = sig.bytesize == 65 ? :schnorr : :ecdsa
        Tapyrus::Key.new(pubkey: pubkey).verify(sig[0...-1], sighash, algo: algo)
      rescue StandardError
        false
      end

      # The locktime of the transaction, or nil when the required locktimes of the inputs
      # contradict each other. Used to compare a hypothetical set of fields against the current
      # one, where a contradiction counts as a change rather than as an error of its own.
      def locktime_or_nil
        locktime
      rescue Error
        nil
      end

      # Apply the change +block+ makes and keep it only if the locktime of the transaction is
      # unchanged, because every signature commits to the locktime. The block returns a lambda
      # which undoes its change. A PSTT which holds no signature is changed unconditionally.
      # @param [String] what the subject of the error message.
      # @raise [Tapyrus::PSTT::Error] if the change alters the locktime.
      def keeping_locktime(what)
        unless signed?
          yield
          return
        end
        before = locktime_or_nil
        undo = yield
        after = locktime_or_nil
        return if before && after && before == after
        undo.call
        raise Error, "#{what} changes the locktime of a PSTT which already contains signatures."
      end

      # Check that +value+ does not relax PSTT_GLOBAL_TX_MODIFIABLE. See #tx_modifiable=.
      def validate_tx_modifiable_tightens!(value)
        before = tx_modifiable.to_i
        after = value.to_i
        permissive = TxModifiable::INPUTS | TxModifiable::OUTPUTS
        loosened = (after & ~before & permissive) | (before & ~after & TxModifiable::HAS_SIGHASH_SINGLE)
        return if loosened.zero?
        raise Error, "PSTT_GLOBAL_TX_MODIFIABLE must not be relaxed once the PSTT contains signatures."
      end

      # Check that the two PSTTs agree on the sequence number of every input.
      #
      # The identifier is computed with every sequence number set to 0, so two PSTTs which
      # disagree about one still identify as the same PSTT. Merging records by their complete key
      # keeps this PSTT's value and discards the other's, which would invalidate every signature
      # of the other which commits to the value it carried. This is therefore the conflict a
      # Combiner refuses rather than resolves.
      def validate_sequences_agree!(other)
        inputs.each_with_index do |input, index|
          next if input.final_sequence == other.inputs[index].final_sequence
          raise Error, "Input #{index} has a different sequence number in the two PSTTs."
        end
      end

      # PSTT_GLOBAL_TX_MODIFIABLE of a combined PSTT.
      #
      # Merging records by their complete key keeps one copy's value and discards the other's,
      # which would resurrect a flag the other copy cleared when it collected a signature and
      # leave a PSTT which carries a SIGHASH_ALL signature and still claims to accept further
      # inputs. A flag which permits a modification therefore survives only while both copies
      # permit it; every other bit, Has SIGHASH_SINGLE included, is the union of the two.
      def merge_tx_modifiable(mine, theirs)
        return nil if mine.nil? && theirs.nil?
        permissive = TxModifiable::INPUTS | TxModifiable::OUTPUTS
        a = mine.to_i
        b = theirs.to_i
        (a & b & permissive) | ((a | b) & ~permissive)
      end

      def update_tx_modifiable_after_sign(hash_type)
        base = hash_type & 0x1f
        flags = tx_modifiable
        if flags
          flags &= ~TxModifiable::INPUTS if (hash_type & SIGHASH_TYPE[:anyonecanpay]).zero?
          flags &= ~TxModifiable::OUTPUTS unless base == SIGHASH_TYPE[:none]
        end
        flags = flags.to_i | TxModifiable::HAS_SIGHASH_SINGLE if base == SIGHASH_TYPE[:single]
        self.tx_modifiable = flags
      end

      def merge_records(a, b)
        (a + b).each_with_object({}) { |record, merged| merged[record.key] ||= record }.values
      end
    end
  end
end
