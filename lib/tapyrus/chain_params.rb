require 'yaml'

module Tapyrus

  # Network parameter class
  class ChainParams

    attr_reader :network
    attr_reader :magic_head
    attr_reader :message_magic
    attr_reader :address_version
    attr_reader :p2sh_version
    attr_reader :cp2pkh_version
    attr_reader :cp2sh_version
    attr_reader :privkey_version
    attr_reader :extended_privkey_version
    attr_reader :extended_pubkey_version
    attr_reader :bip49_pubkey_p2wpkh_p2sh_version
    attr_reader :bip49_privkey_p2wpkh_p2sh_version
    attr_reader :bip49_pubkey_p2wsh_p2sh_version
    attr_reader :bip49_privkey_p2wsh_p2sh_version
    attr_reader :bip84_pubkey_p2wpkh_version
    attr_reader :bip84_privkey_p2wpkh_version
    attr_reader :bip84_pubkey_p2wsh_version
    attr_reader :bip84_privkey_p2wsh_version
    attr_reader :default_port
    attr_reader :rpc_port
    attr_reader :protocol_version
    attr_reader :retarget_interval
    attr_reader :retarget_time
    attr_reader :target_spacing
    attr_reader :max_money
    attr_reader :bip34_height
    attr_reader :proof_of_work_limit
    attr_reader :dns_seeds
    attr_reader :bip44_coin_type

    attr_accessor :dust_relay_fee

    # production genesis
    def self.prod
      init('prod')
    end

    # development genesis
    def self.dev
      init('dev')
    end

    def prod?
      network == 'prod'
    end

    def dev?
      network == 'dev'
    end

    def self.init(name)
      i = YAML.load(File.open("#{__dir__}/chainparams/#{name}.yml"))
      i.dust_relay_fee ||= Tapyrus::DUST_RELAY_TX_FEE
      i
    end

    private_class_method :init
  end

end