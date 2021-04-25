module Tapyrus
  # https://bitcoin.org/en/developer-reference#opcodes
  module Opcodes
    module_function

    # https://en.bitcoin.it/wiki/Script#Constants
    OP_0 = 0x00
    OP_1 = 0x51
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f

    # https://en.bitcoin.it/wiki/Script#Flow_control
    OP_NOP = 0x61
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # https://en.bitcoin.it/wiki/Script#Stack
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72

    # https://en.bitcoin.it/wiki/Script#Splice
    OP_CAT = 0x7e # disabled
    OP_SUBSTR = 0x7f # disabled
    OP_LEFT = 0x80 # disabled
    OP_RIGHT = 0x81 # disabled
    OP_SIZE = 0x82

    # https://en.bitcoin.it/wiki/Script#Bitwise_logic
    OP_INVERT = 0x83 # disabled
    OP_AND = 0x84 # disabled
    OP_OR = 0x85 # disabled
    OP_XOR = 0x86 # disabled
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88

    # https://en.bitcoin.it/wiki/Script#Arithmetic
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d # disabled
    OP_2DIV = 0x8e # disabled
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92
    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95 # disabled
    OP_DIV = 0x96 # disabled
    OP_MOD = 0x97 # disabled
    OP_LSHIFT = 0x98 # disabled
    OP_RSHIFT = 0x99 # disabled
    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4
    OP_WITHIN = 0xa5

    # https://en.bitcoin.it/wiki/Script#Crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # https://en.bitcoin.it/wiki/Script#Locktime
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY = OP_CLTV = 0xb1
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY = OP_CSV = 0xb2

    # https://en.bitcoin.it/wiki/Script#Reserved_words
    OP_RESERVED = 0x50
    OP_VER = 0x62
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    OP_NOP1 = 0xb0
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    # https://en.bitcoin.it/wiki/Script#Pseudo-words
    OP_PUBKEYHASH = 0xfd
    OP_PUBKEY = 0xfe
    OP_INVALIDOPCODE = 0xff

    # tapyrus extension
    OP_CHECKDATASIG = 0xba
    OP_CHECKDATASIGVERIFY = 0xbb
    OP_COLOR = 0xbc

    DUPLICATE_KEY = [:OP_NOP2, :OP_NOP3]
    OPCODES_MAP =
      Hash[
        *(constants.grep(/^OP_/) - [:OP_NOP2, :OP_NOP3, :OP_CHECKLOCKTIMEVERIFY, :OP_CHECKSEQUENCEVERIFY]).map do |c|
          [const_get(c), c.to_s]
        end.flatten
      ]
    NAME_MAP = Hash[*constants.grep(/^OP_/).map { |c| [c.to_s, const_get(c)] }.flatten]

    def opcode_to_name(opcode)
      return OPCODES_MAP[opcode].delete('OP_') if opcode == OP_0 || (opcode <= OP_16 && opcode >= OP_1)
      OPCODES_MAP[opcode]
    end

    def name_to_opcode(name)
      return NAME_MAP['OP_' + name] if name =~ /^\d/ && name.to_i < 17 && name.to_i > -1
      NAME_MAP[name]
    end

    # whether opcode is predefined opcode
    def defined?(opcode)
      !opcode_to_name(opcode).nil?
    end

    def small_int_to_opcode(int)
      return OP_0 if int == 0
      return OP_1NEGATE if int == -1
      return OP_1 + (int - 1) if int >= 1 && int <= 16
      nil
    end

    def opcode_to_small_int(opcode)
      return 0 if opcode == ''.b || opcode == OP_0
      return -1 if opcode == OP_1NEGATE
      return opcode - (OP_1 - 1) if opcode >= OP_1 && opcode <= OP_16
      nil
    end
  end
end
