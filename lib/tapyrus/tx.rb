# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

module Tapyrus

  # Transaction class
  class Tx
    include Tapyrus::HexConverter

    MAX_STANDARD_VERSION = 2

    # The maximum weight for transactions we're willing to relay/mine
    MAX_STANDARD_TX_WEIGHT = 400000

    attr_accessor :features
    attr_reader :inputs
    attr_reader :outputs
    attr_accessor :lock_time

    def initialize
      @inputs = []
      @outputs = []
      @features = 1
      @lock_time = 0
    end

    alias_method :in, :inputs
    alias_method :out, :outputs

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      tx = new
      tx.features = buf.read(4).unpack('V').first

      in_count = Tapyrus.unpack_var_int_from_io(buf)

      in_count.times do
        tx.inputs << TxIn.parse_from_payload(buf)
      end

      out_count = Tapyrus.unpack_var_int_from_io(buf)
      out_count.times do
        tx.outputs << TxOut.parse_from_payload(buf)
      end

      tx.lock_time = buf.read(4).unpack('V').first

      tx
    end

    def hash
      to_hex.to_i(16)
    end

    def tx_hash
      Tapyrus.double_sha256(to_payload).bth
    end

    def txid
      buf = [features].pack('V')
      buf << Tapyrus.pack_var_int(inputs.length) << inputs.map{|i|i.to_payload(use_malfix: true)}.join
      buf << Tapyrus.pack_var_int(outputs.length) << outputs.map(&:to_payload).join
      buf << [lock_time].pack('V')
      Tapyrus.double_sha256(buf).reverse.bth
    end

    def to_payload
      buf = [features].pack('V')
      buf << Tapyrus.pack_var_int(inputs.length) << inputs.map(&:to_payload).join
      buf << Tapyrus.pack_var_int(outputs.length) << outputs.map(&:to_payload).join
      buf << [lock_time].pack('V')
      buf
    end

    def coinbase_tx?
      inputs.length == 1 && inputs.first.coinbase?
    end

    def ==(other)
      to_payload == other.to_payload
    end

    # check this tx is standard.
    def standard?
      return false if features > MAX_STANDARD_VERSION
      inputs.each do |i|
        # Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed keys (remember the 520 byte limit on redeemScript size).
        # That works out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        # bytes of scriptSig, which we round off to 1650 bytes for some minor future-proofing.
        # That's also enough to spend a 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not considered standard.
        return false if i.script_sig.size > 1650
        return false unless i.script_sig.push_only?
      end
      data_count = 0
      outputs.each do |o|
        return false unless o.script_pubkey.standard?
        data_count += 1 if o.script_pubkey.op_return?
        # TODO add non P2SH multisig relay(permitbaremultisig)
        return false if o.dust?
      end
      return false if data_count > 1
      true
    end

    # The serialized transaction size
    def size
      to_payload.bytesize
    end

    # get signature hash
    # @param [Integer] input_index input index.
    # @param [Integer] hash_type signature hash type
    # @param [Tapyrus::Script] output_script script pubkey or script code. if script pubkey is P2WSH, set witness script to this.
    # @param [Integer] amount tapyrus amount locked in input. required for witness input only.
    # @param [Integer] skip_separator_index If output_script is P2WSH and output_script contains any OP_CODESEPARATOR,
    # the script code needs  is the witnessScript but removing everything up to and including the last executed OP_CODESEPARATOR before the signature checking opcode being executed.
    def sighash_for_input(input_index, output_script, hash_type: SIGHASH_TYPE[:all],
                          sig_version: :base, amount: nil, skip_separator_index: 0)
      raise ArgumentError, 'input_index must be specified.' unless input_index
      raise ArgumentError, 'does not exist input corresponding to input_index.' if input_index >= inputs.size
      raise ArgumentError, 'script_pubkey must be specified.' unless output_script
      raise ArgumentError, 'unsupported sig version specified.' unless SIG_VERSION.include?(sig_version)
      sighash_for_legacy(input_index, output_script, hash_type)
    end

    # verify input signature.
    # @param [Integer] input_index
    # @param [Tapyrus::Script] script_pubkey the script pubkey for target input.
    # @param [Integer] amount the amount of tapyrus, require for witness program only.
    # @param [Array] flags the flags used when execute script interpreter.
    def verify_input_sig(input_index, script_pubkey, amount: nil, flags: STANDARD_SCRIPT_VERIFY_FLAGS)
      if script_pubkey.p2sh?
        flags << SCRIPT_VERIFY_P2SH
      end
      verify_input_sig_for_legacy(input_index, script_pubkey, flags)
    end

    def to_h
      {
          txid: txid, hash: tx_hash, features: features, size: size, locktime: lock_time,
          vin: inputs.map(&:to_h), vout: outputs.map.with_index{|tx_out, index| tx_out.to_h.merge({n: index})}
      }
    end

    # Verify transaction validity.
    # @return [Boolean] whether this tx is valid or not.
    def valid?
      state = Tapyrus::ValidationState.new
      validation = Tapyrus::Validation.new
      validation.check_tx(self, state) && state.valid?
    end

    private

    # generate sighash with legacy format
    def sighash_for_legacy(index, script_code, hash_type)
      ins = inputs.map.with_index do |i, idx|
        if idx == index
          i.to_payload(script_code.delete_opcode(Tapyrus::Opcodes::OP_CODESEPARATOR))
        else
          case hash_type & 0x1f
            when SIGHASH_TYPE[:none], SIGHASH_TYPE[:single]
              i.to_payload(Tapyrus::Script.new, 0)
            else
              i.to_payload(Tapyrus::Script.new)
          end
        end
      end

      outs = outputs.map(&:to_payload)
      out_size = Tapyrus.pack_var_int(outputs.size)

      case hash_type & 0x1f
        when SIGHASH_TYPE[:none]
          outs = ''
          out_size = Tapyrus.pack_var_int(0)
        when SIGHASH_TYPE[:single]
          return "\x01".ljust(32, "\x00") if index >= outputs.size
          outs = outputs[0...(index + 1)].map.with_index { |o, idx| (idx == index) ? o.to_payload : o.to_empty_payload }.join
          out_size = Tapyrus.pack_var_int(index + 1)
      end

      if hash_type & SIGHASH_TYPE[:anyonecanpay] != 0
        ins = [ins[index]]
      end

      buf = [[features].pack('V'), Tapyrus.pack_var_int(ins.size),
          ins, out_size, outs, [lock_time, hash_type].pack('VV')].join

      Tapyrus.double_sha256(buf)
    end


    # verify input signature for legacy tx.
    def verify_input_sig_for_legacy(input_index, script_pubkey, flags)
      script_sig = inputs[input_index].script_sig
      checker = Tapyrus::TxChecker.new(tx: self, input_index: input_index)
      interpreter = Tapyrus::ScriptInterpreter.new(checker: checker, flags: flags)

      interpreter.verify_script(script_sig, script_pubkey)
    end

  end

end
