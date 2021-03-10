# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

module Tapyrus

  # tapyrus script
  class Script
    include Tapyrus::HexConverter
    include Tapyrus::Opcodes

    attr_accessor :chunks

    def initialize
      @chunks = []
    end

    # generate P2PKH script
    def self.to_p2pkh(pubkey_hash)
      new << OP_DUP << OP_HASH160 << pubkey_hash << OP_EQUALVERIFY << OP_CHECKSIG
    end

    # generate m of n multisig p2sh script
    # @param [String] m the number of signatures required for multisig
    # @param [Array] pubkeys array of public keys that compose multisig
    # @return [Script, Script] first element is p2sh script, second one is redeem script.
    def self.to_p2sh_multisig_script(m, pubkeys)
      redeem_script = to_multisig_script(m, pubkeys)
      [redeem_script.to_p2sh, redeem_script]
    end

    # generate p2sh script.
    # @param [String] script_hash script hash for P2SH
    # @return [Script] P2SH script
    def self.to_p2sh(script_hash)
      Script.new << OP_HASH160 << script_hash << OP_EQUAL
    end

    # generate p2sh script with this as a redeem script
    # @return [Script] P2SH script
    def to_p2sh
      Script.to_p2sh(to_hash160)
    end

    # generate cp2pkh script
    # @param [ColorIdentifier] color identifier
    # @param [String] hash160 of pubkey
    # @return [Script] CP2PKH script
    # @raise [ArgumentError] if color_id is nil or invalid
    def self.to_cp2pkh(color_id, pubkey_hash)
      raise ArgumentError, 'Specified color identifier is invalid' unless color_id&.valid?
      new << color_id.to_payload << OP_COLOR << OP_DUP << OP_HASH160 << pubkey_hash << OP_EQUALVERIFY << OP_CHECKSIG
    end

    # generate cp2sh script
    # @param [ColorIdentifier] color identifier
    # @param [String] hash160 of script
    # @return [Script] CP2SH script
    # @raise [ArgumentError] if color_id is nil or invalid
    def self.to_cp2sh(color_id, script_hash)
      raise ArgumentError, 'Specified color identifier is invalid' unless color_id&.valid?
      new << color_id.to_payload << OP_COLOR << OP_HASH160 << script_hash << OP_EQUAL
    end

    # Add color identifier to existing p2pkh or p2sh
    # @param [ColorIdentifier] color identifier
    # @return [Script] CP2PKH or CP2SH script
    # @raise [ArgumentError] if color_id is nil or invalid
    # @raise [RuntimeError] if script is neither p2pkh nor p2sh
    def add_color(color_id)
      raise ArgumentError, 'Specified color identifier is invalid' unless color_id&.valid?
      raise RuntimeError, 'Only p2pkh and p2sh can add color' unless p2pkh? or p2sh?
      Tapyrus::Script.new.tap do |s|
        s << color_id.to_payload << OP_COLOR
        s.chunks += self.chunks
      end
    end

    # Remove color identifier from cp2pkh or cp2sh
    # @param [ColorIdentifier] color identifier
    # @return [Script] P2PKH or P2SH script
    # @raise [RuntimeError] if script is neither cp2pkh nor cp2sh
    def remove_color
      raise RuntimeError, 'Only cp2pkh and cp2sh can remove color' unless cp2pkh? or cp2sh?

      Tapyrus::Script.new.tap do |s|
        s.chunks = self.chunks[2..-1]
      end
    end

    def get_multisig_pubkeys
      num = Tapyrus::Opcodes.opcode_to_small_int(chunks[-2].bth.to_i(16))
      (1..num).map{ |i| chunks[i].pushed_data }
    end

    # generate m of n multisig script
    # @param [String] m the number of signatures required for multisig
    # @param [Array] pubkeys array of public keys that compose multisig
    # @return [Script] multisig script.
    def self.to_multisig_script(m, pubkeys, sort: false)
      pubkeys = pubkeys.sort if sort
      new << m << pubkeys << pubkeys.size << OP_CHECKMULTISIG
    end

    # generate script from string.
    def self.from_string(string)
      script = new
      string.split(' ').each do |v|
        opcode = Opcodes.name_to_opcode(v)
        if opcode
          script << (v =~ /^\d/ && Opcodes.small_int_to_opcode(v.ord) ? v.ord : opcode)
        else
          script << (v =~ /^[0-9]+$/ ? v.to_i : v)
        end
      end
      script
    end

    # generate script from addr.
    # @param [String] addr address.
    # @return [Tapyrus::Script] parsed script.
    def self.parse_from_addr(addr)
      begin
        segwit_addr = Bech32::SegwitAddr.new(addr)
        raise 'Invalid hrp.' unless Tapyrus.chain_params.bech32_hrp == segwit_addr.hrp
        Tapyrus::Script.parse_from_payload(segwit_addr.to_script_pubkey.htb)
      rescue Exception => e
        hex, addr_version = Tapyrus.decode_base58_address(addr)
        case addr_version
        when Tapyrus.chain_params.address_version
          Tapyrus::Script.to_p2pkh(hex)
        when Tapyrus.chain_params.p2sh_version
          Tapyrus::Script.to_p2sh(hex)
        when Tapyrus.chain_params.cp2pkh_version
          color = Tapyrus::Color::ColorIdentifier.parse_from_payload(hex[0..65].htb)
          Tapyrus::Script.to_cp2pkh(color, hex[66..-1])
        when Tapyrus.chain_params.cp2sh_version
          color = Tapyrus::Color::ColorIdentifier.parse_from_payload(hex[0..65].htb)
          Tapyrus::Script.to_cp2sh(color, hex[66..-1])
        else
          throw e
        end
      end
    end

    def self.parse_from_payload(payload)
      s = new
      buf = StringIO.new(payload)
      until buf.eof?
        opcode = buf.read(1)
        if opcode.pushdata?
          pushcode = opcode.ord
          packed_size = nil
          len = case pushcode
                  when OP_PUSHDATA1
                    packed_size = buf.read(1)
                    packed_size.unpack('C').first
                  when OP_PUSHDATA2
                    packed_size = buf.read(2)
                    packed_size.unpack('v').first
                  when OP_PUSHDATA4
                    packed_size = buf.read(4)
                    packed_size.unpack('V').first
                  else
                    pushcode if pushcode < OP_PUSHDATA1
                end
          if len
            s.chunks << [len].pack('C') if buf.eof?
            unless buf.eof?
              chunk = (packed_size ? (opcode + packed_size) : (opcode)) + buf.read(len)
              s.chunks << chunk
            end
          end
        else
          if Opcodes.defined?(opcode.ord)
            s << opcode.ord
          else
            s.chunks << (opcode + buf.read) # If opcode is invalid, put all remaining data in last chunk.
          end
        end
      end
      s
    end

    def to_payload
      chunks.join
    end

    def empty?
      chunks.size == 0
    end

    def addresses
      return [p2pkh_addr] if p2pkh?
      return [p2sh_addr] if p2sh?
      return [cp2pkh_addr] if cp2pkh?
      return [cp2sh_addr] if cp2sh?
      return get_multisig_pubkeys.map{|pubkey| Tapyrus::Key.new(pubkey: pubkey.bth).to_p2pkh} if multisig?
      []
    end

    # check whether standard script.
    def standard?
      p2pkh? | p2sh? | multisig? | standard_op_return?
    end

    # whether this script is a P2PKH format script.
    def p2pkh?
      return false unless chunks.size == 5
      [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] ==
          (chunks[0..1]+ chunks[3..4]).map(&:ord) && chunks[2].bytesize == 21
    end

    def p2sh?
      return false unless chunks.size == 3
      OP_HASH160 == chunks[0].ord && OP_EQUAL == chunks[2].ord && chunks[1].bytesize == 21
    end

    def multisig?
      return false if chunks.size < 4 || chunks.last.ord != OP_CHECKMULTISIG
      pubkey_count = Opcodes.opcode_to_small_int(chunks[-2].opcode)
      sig_count = Opcodes.opcode_to_small_int(chunks[0].opcode)
      return false unless pubkey_count || sig_count
      sig_count <= pubkey_count
    end

    def op_return?
      chunks.size >= 1 && chunks[0].ord == OP_RETURN
    end

    def standard_op_return?
      op_return? && size <= MAX_OP_RETURN_RELAY &&
          (chunks.size == 1 || chunks[1].opcode <= OP_16)
    end

    # Return whether this script is a CP2PKH format script or not.
    # @return [Boolean] true if this script is cp2pkh, otherwise false.
    def cp2pkh?
      return false unless chunks.size == 7
      return false unless chunks[0].bytesize == 34
      return false unless Tapyrus::Color::ColorIdentifier.parse_from_payload(chunks[0].pushed_data)&.valid?
      return false unless chunks[1].ord == OP_COLOR
      [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] ==
          (chunks[2..3]+ chunks[5..6]).map(&:ord) && chunks[4].bytesize == 21
    end

    # Return whether this script is a CP2SH format script or not.
    # @return [Boolean] true if this script is cp2pkh, otherwise false.
    def cp2sh?
      return false unless chunks.size == 5
      return false unless chunks[0].bytesize == 34
      return false unless Tapyrus::Color::ColorIdentifier.parse_from_payload(chunks[0].pushed_data)&.valid?
      return false unless chunks[1].ord == OP_COLOR
      OP_HASH160 == chunks[2].ord && OP_EQUAL == chunks[4].ord && chunks[3].bytesize == 21
    end
  
    # Return whether this script represents colored coin.
    # @return [Boolean] true if this script is colored, otherwise false.
    def colored?
      cp2pkh? || cp2sh?
    end

    # Return color identifier for this script.
    # @return [ColorIdentifer] color identifier for this script if this script is colored. return nil if this script is not colored.
    def color_id
      return nil unless colored?

      Tapyrus::Color::ColorIdentifier.parse_from_payload(chunks[0].pushed_data)
    end

    def op_return_data
      return nil unless op_return?
      return nil if chunks.size == 1
      chunks[1].pushed_data
    end

    # whether data push only script which dose not include other opcode
    def push_only?
      chunks.each do |c|
        return false if !c.opcode.nil? && c.opcode > OP_16
      end
      true
    end

    # get public keys in the stack.
    # @return[Array[String]] an array of the pubkeys with hex format.
    def get_pubkeys
      chunks.select{|c|c.pushdata? && [33, 65].include?(c.pushed_data.bytesize) && [2, 3, 4, 6, 7].include?(c.pushed_data[0].bth.to_i(16))}.map{|c|c.pushed_data.bth}
    end

    # returns the self payload. ScriptInterpreter does not use this.
    def to_script_code(skip_separator_index = 0)
      payload = to_payload
      if skip_separator_index > 0
        payload = subscript_codeseparator(skip_separator_index)
      end
      Tapyrus.pack_var_string(payload)
    end

    # append object to payload
    def <<(obj)
      if obj.is_a?(Integer)
        push_int(obj)
      elsif obj.is_a?(String)
        append_data(obj)
      elsif obj.is_a?(Array)
        obj.each { |o| self.<< o}
        self
      end
    end

    # push integer to stack.
    def push_int(n)
      begin
        append_opcode(n)
      rescue ArgumentError
        append_data(Script.encode_number(n))
      end
      self
    end

    # append opcode to payload
    # @param [Integer] opcode append opcode which defined by Tapyrus::Opcodes
    # @return [Script] return self
    def append_opcode(opcode)
      opcode = Opcodes.small_int_to_opcode(opcode) if -1 <= opcode && opcode <= 16
      raise ArgumentError, "specified invalid opcode #{opcode}." unless Opcodes.defined?(opcode)
      chunks << opcode.chr
      self
    end

    # append data to payload with pushdata opcode
    # @param [String] data append data. this data is not binary
    # @return [Script] return self
    def append_data(data)
      data = Encoding::ASCII_8BIT == data.encoding ? data : data.htb
      chunks << Tapyrus::Script.pack_pushdata(data)
      self
    end

    # Check the item is in the chunk of the script.
    def include?(item)
      chunk_item = if item.is_a?(Integer)
                     item.chr
                   elsif item.is_a?(String)
                     data = Encoding::ASCII_8BIT == item.encoding ? item : item.htb
                     Tapyrus::Script.pack_pushdata(data)
                   end
      return false unless chunk_item
      chunks.include?(chunk_item)
    end

    def to_s
      chunks.map { |c|
        case c
        when Integer
          opcode_to_name(c)
        when String
          return c if c.empty?
          if c.pushdata?
            v = Opcodes.opcode_to_small_int(c.ord)
            if v
              v
            else
              data = c.pushed_data
              if data.bytesize <= 4
                Script.decode_number(data.bth) # for scriptnum
              else
                data.bth
              end
            end
          else
            opcode = Opcodes.opcode_to_name(c.ord)
            opcode ? opcode : 'OP_UNKNOWN [error]'
          end
        end
      }.join(' ')
    end

    # generate sha-256 hash for payload
    def to_sha256
      Tapyrus.sha256(to_payload).bth
    end

    # generate hash160 hash for payload
    def to_hash160
      Tapyrus.hash160(to_hex)
    end

    # script size
    def size
      to_payload.bytesize
    end

    # execute script interpreter using this script for development.
    def run
      Tapyrus::ScriptInterpreter.eval(Tapyrus::Script.new, self.dup)
    end

    # encode int value to script number hex.
    # The stacks hold byte vectors.
    # When used as numbers, byte vectors are interpreted as little-endian variable-length integers
    # with the most significant bit determining the sign of the integer.
    # Thus 0x81 represents -1. 0x80 is another representation of zero (so called negative 0).
    # Positive 0 is represented by a null-length vector.
    # Byte vectors are interpreted as Booleans where False is represented by any representation of zero,
    # and True is represented by any representation of non-zero.
    def self.encode_number(i)
      return '' if i == 0
      negative = i < 0

      hex = i.abs.to_even_length_hex
      hex = '0' + hex unless (hex.length % 2).zero?
      v = hex.htb.reverse # change endian

      v = v << (negative ? 0x80 : 0x00) unless (v[-1].unpack('C').first & 0x80) == 0
      v[-1] = [v[-1].unpack('C').first | 0x80].pack('C') if negative
      v.bth
    end

    # decode script number hex to int value
    def self.decode_number(s)
      v = s.htb.reverse
      return 0 if v.length.zero?
      mbs = v[0].unpack('C').first
      v[0] = [mbs - 0x80].pack('C') unless (mbs & 0x80) == 0
      result = v.bth.to_i(16)
      result = -result unless (mbs & 0x80) == 0
      result
    end

    # binary +data+ convert pushdata which contains data length and append PUSHDATA opcode if necessary.
    def self.pack_pushdata(data)
      size = data.bytesize
      header = if size < OP_PUSHDATA1
                 [size].pack('C')
               elsif size < 0xff
                 [OP_PUSHDATA1, size].pack('CC')
               elsif size < 0xffff
                 [OP_PUSHDATA2, size].pack('Cv')
               elsif size < 0xffffffff
                 [OP_PUSHDATA4, size].pack('CV')
               else
                 raise ArgumentError, 'data size is too big.'
               end
      header + data
    end

    # subscript this script to the specified range.
    def subscript(*args)
      s = self.class.new
      s.chunks = chunks[*args]
      s
    end

    # removes chunks matching subscript byte-for-byte and returns as a new object.
    def find_and_delete(subscript)
      raise ArgumentError, 'subscript must be Tapyrus::Script' unless subscript.is_a?(Script)
      return self if subscript.chunks.empty?
      buf = []
      i = 0
      result = Script.new
      chunks.each do |chunk|
        sub_chunk = subscript.chunks[i]
        if chunk.start_with?(sub_chunk)
          if chunk == sub_chunk
            buf << chunk
            i += 1
            (i = 0; buf.clear) if i == subscript.chunks.size # matched the whole subscript
          else # matched the part of head
            i = 0
            tmp = chunk.dup
            tmp.slice!(sub_chunk)
            result.chunks << tmp
          end
        else
          result.chunks << buf.join unless buf.empty?
          if buf.first == chunk
            i = 1
            buf = [chunk]
          else
            i = 0
            result.chunks << chunk
          end
        end
      end
      result
    end

    # remove all occurences of opcode. Typically it's OP_CODESEPARATOR.
    def delete_opcode(opcode)
      @chunks = chunks.select{|chunk| chunk.ord != opcode}
      self
    end

    # Returns a script that deleted the script before the index specified by separator_index.
    def subscript_codeseparator(separator_index)
      buf = []
      process_separator_index = 0
      chunks.each{|chunk|
        buf << chunk if process_separator_index == separator_index
        if chunk.ord == OP_CODESEPARATOR && process_separator_index < separator_index
          process_separator_index += 1
        end
      }
      buf.join
    end

    def ==(other)
      return false unless other
      chunks == other.chunks
    end

    def type
      return 'pubkeyhash' if p2pkh?
      return 'scripthash' if p2sh?
      return 'multisig' if multisig?
      'nonstandard'
    end

    def to_h
      h = {asm: to_s, hex: to_hex, type: type}
      addrs = addresses
      unless addrs.empty?
        h[:req_sigs] = multisig? ? Tapyrus::Opcodes.opcode_to_small_int(chunks[0].bth.to_i(16)) :addrs.size
        h[:addresses] = addrs
      end
      h
    end

    # Returns whether the script is guaranteed to fail at execution, regardless of the initial stack.
    # This allows outputs to be pruned instantly when entering the UTXO set.
    # @return [Boolean] whether the script is guaranteed to fail at execution
    def unspendable?
      (size > 0 && op_return?) || size > Tapyrus::MAX_SCRIPT_SIZE
    end

    private

    # generate p2pkh address. if script dose not p2pkh, return nil.
    def p2pkh_addr
      return nil unless p2pkh?
      hash160 = chunks[2].pushed_data.bth
      Tapyrus.encode_base58_address(hash160, Tapyrus.chain_params.address_version)
    end

    # generate p2sh address. if script dose not p2sh, return nil.
    def p2sh_addr
      return nil unless p2sh?
      hash160 = chunks[1].pushed_data.bth
      Tapyrus.encode_base58_address(hash160, Tapyrus.chain_params.p2sh_version)
    end

    # generate cp2pkh address. if script dose not cp2pkh, return nil.
    def cp2pkh_addr
      return nil unless cp2pkh?

      color_id = chunks[0].pushed_data.bth
      hash160 = chunks[4].pushed_data.bth
      Tapyrus.encode_base58_address(color_id + hash160, Tapyrus.chain_params.cp2pkh_version)
    end

    # generate cp2sh address. if script dose not cp2sh, return nil.
    def cp2sh_addr
      return nil unless cp2sh?

      color_id = chunks[0].pushed_data.bth
      hash160 = chunks[3].pushed_data.bth
      Tapyrus.encode_base58_address(color_id + hash160, Tapyrus.chain_params.cp2sh_version)
    end
  end

end
