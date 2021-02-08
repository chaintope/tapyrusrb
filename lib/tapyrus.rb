# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

require 'tapyrus/version'
require 'eventmachine'
require 'ecdsa'
require 'securerandom'
require 'json'
require 'ffi'
require 'observer'
require 'tmpdir'
require_relative 'openassets'
require_relative 'schnorr'

module Tapyrus

  autoload :Ext, 'tapyrus/ext'
  autoload :Util, 'tapyrus/util'
  autoload :ChainParams, 'tapyrus/chain_params'
  autoload :Message, 'tapyrus/message'
  autoload :Logger, 'tapyrus/logger'
  autoload :Block, 'tapyrus/block'
  autoload :BlockHeader, 'tapyrus/block_header'
  autoload :Tx, 'tapyrus/tx'
  autoload :Script, 'tapyrus/script/script'
  autoload :Multisig, 'tapyrus/script/multisig'
  autoload :ScriptInterpreter, 'tapyrus/script/script_interpreter'
  autoload :ScriptError, 'tapyrus/script/script_error'
  autoload :TxChecker, 'tapyrus/script/tx_checker'
  autoload :TxIn, 'tapyrus/tx_in'
  autoload :TxOut, 'tapyrus/tx_out'
  autoload :OutPoint, 'tapyrus/out_point'
  autoload :MerkleTree, 'tapyrus/merkle_tree'
  autoload :Key, 'tapyrus/key'
  autoload :ExtKey, 'tapyrus/ext_key'
  autoload :ExtPubkey, 'tapyrus/ext_key'
  autoload :Opcodes, 'tapyrus/opcodes'
  autoload :Node, 'tapyrus/node'
  autoload :Base58, 'tapyrus/base58'
  autoload :Secp256k1, 'tapyrus/secp256k1'
  autoload :Mnemonic, 'tapyrus/mnemonic'
  autoload :ValidationState, 'tapyrus/validation'
  autoload :Network, 'tapyrus/network'
  autoload :Store, 'tapyrus/store'
  autoload :RPC, 'tapyrus/rpc'
  autoload :Wallet, 'tapyrus/wallet'
  autoload :BloomFilter, 'tapyrus/bloom_filter'
  autoload :KeyPath, 'tapyrus/key_path'
  autoload :SLIP39, 'tapyrus/slip39'
  autoload :Color, 'tapyrus/script/color'
  autoload :Errors, 'tapyrus/errors'

  require_relative 'tapyrus/constants'
  require_relative 'tapyrus/ext/ecdsa'

  extend Util

  @chain_param = :prod

  # set tapyrus network chain params
  def self.chain_params=(name)
    raise "chain params for #{name} is not defined." unless %i(prod dev).include?(name.to_sym)
    @current_chain = nil
    @chain_param = name.to_sym
  end

  # current tapyrus network chain params.
  def self.chain_params
    return @current_chain if @current_chain
    case @chain_param
    when :prod
      @current_chain = Tapyrus::ChainParams.prod
    when :dev
      @current_chain = Tapyrus::ChainParams.dev
    end
    @current_chain
  end

  # base dir path that store blockchain data and wallet data
  def self.base_dir
    "#{Dir.home}/.tapyrusrb/#{@chain_param}"
  end

  # get secp implementation module
  def self.secp_impl
    path = ENV['SECP256K1_LIB_PATH']
    (path && File.exist?(path)) ? Tapyrus::Secp256k1::Native : Tapyrus::Secp256k1::Ruby
  end

  def self.hmac_sha512(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA512'), key, data)
  end

  def self.hmac_sha256(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), key, data)
  end

  class ::String
    # binary convert to hex string
    def bth
      unpack('H*').first
    end

    # hex string convert to binary
    def htb
      [self].pack('H*')
    end

    # binary convert to integer
    def bti
      bth.to_i(16)
    end

    # reverse hex string endian
    def rhex
      htb.reverse.bth
    end

    # get opcode
    def opcode
      force_encoding(Encoding::ASCII_8BIT).ord
    end

    def opcode?
      !pushdata?
    end

    def push_opcode?
      [Tapyrus::Opcodes::OP_PUSHDATA1, Tapyrus::Opcodes::OP_PUSHDATA2, Tapyrus::Opcodes::OP_PUSHDATA4].include?(opcode)
    end

    # whether data push only?
    def pushdata?
      opcode <= Tapyrus::Opcodes::OP_PUSHDATA4 && opcode > Tapyrus::Opcodes::OP_0
    end

    def pushed_data
      return nil unless pushdata?
      offset = 1
      case opcode
      when Tapyrus::Opcodes::OP_PUSHDATA1
        offset += 1
      when Tapyrus::Opcodes::OP_PUSHDATA2
        offset += 2
      when Tapyrus::Opcodes::OP_PUSHDATA4
        offset += 4
      end
      self[offset..-1]
    end

    # whether value is hex or not hex
    # @return [Boolean] return true if data is hex
    def valid_hex?
      !self[/\H/]
    end

  end

  class ::Object

    def build_json
      if self.is_a?(Array)
        "[#{self.map{|o|o.to_h.to_json}.join(',')}]"
      else
        to_h.to_json
      end
    end

    def to_h
      return self if self.is_a?(String)
      instance_variables.inject({}) do |result, var|
        key = var.to_s
        key.slice!(0) if key.start_with?('@')
        value = instance_variable_get(var)
        if value.is_a?(Array)
          result.update(key => value.map{|v|v.to_h})
        else
          result.update(key => value)
        end
      end
    end

  end

  class ::Integer
    def to_even_length_hex
      hex = to_s(16)
      hex.rjust((hex.length / 2.0).ceil * 2, '0')
    end

    def itb
      to_even_length_hex.htb
    end

    # convert bit string
    def to_bits(length = nil )
      if length
        to_s(2).rjust(length, '0')
      else
        to_s(2)
      end
    end
  end

end
