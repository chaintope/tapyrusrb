# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

module Tapyrus
  # transaction input
  class TxIn
    attr_accessor :out_point
    attr_accessor :script_sig
    attr_accessor :sequence

    # Setting nSequence to this value for every input in a transaction disables nLockTime.
    SEQUENCE_FINAL = 0xffffffff

    # If this flag set, TxIn#sequence is NOT interpreted as a relative lock-time.
    SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)

    # If TxIn#sequence encodes a relative lock-time and this flag is set, the relative lock-time has units of 512 seconds,
    # otherwise it specifies blocks with a granularity of 1.
    SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)

    # If TxIn#sequence encodes a relative lock-time, this mask is applied to extract that lock-time from the sequence field.
    SEQUENCE_LOCKTIME_MASK = 0x0000ffff

    def initialize(out_point: nil, script_sig: Tapyrus::Script.new, sequence: SEQUENCE_FINAL)
      @out_point = out_point
      @script_sig = script_sig
      @sequence = sequence
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      i = new
      hash, index = buf.read(36).unpack('a32V')
      i.out_point = OutPoint.new(hash.bth, index)
      sig_length = Tapyrus.unpack_var_int_from_io(buf)
      if sig_length == 0
        i.script_sig = Script.new
      else
        i.script_sig = Script.parse_from_payload(buf.read(sig_length))
      end
      i.sequence = buf.read(4).unpack('V').first
      i
    end

    def coinbase?
      out_point.coinbase?
    end

    def to_payload(script_sig = @script_sig, sequence = @sequence, use_malfix: false)
      p = out_point.to_payload
      unless use_malfix
        p << Tapyrus.pack_var_int(script_sig.to_payload.bytesize)
        p << script_sig.to_payload
      end
      p << [sequence].pack('V')
      p
    end

    def to_h
      sig = script_sig.to_h
      sig.delete(:type)
      h = { txid: out_point.txid, vout: out_point.index, script_sig: sig }
      h[:sequence] = sequence
      h
    end

    def ==(other)
      to_payload == other.to_payload
    end

    # return previous output hash (not txid)
    def prev_hash
      return nil unless out_point
      out_point.tx_hash
    end
  end
end
