module Tapyrus
  class TxBuilder
    def initialize
      @utxos = []
      @incomings = {}
      @outgoings = {}
      @tx = Tapyrus::Tx.new
    end

    # Add utxo for transaction input
    # @param utxo
    def add_utxo(utxo)
      @utxos << utxo
      color_id = utxo[:color_id] || Tapyrus::Color::ColorIdentifier::default
      @incomings[color_id] ||= 0
      @incomings[color_id] += utxo[:value]
      self
    end

    # Issue reissuable token
    # @param address [String] p2pkh or p2sh address.
    def reissuable(script_pubkey, address, value)
      color_id = Tapyrus::Color::ColorIdentifier.reissuable(script_pubkey)
      pay(address, value, color_id)
    end

    # Issue non reissuable token
    # @param address [String] p2pkh or p2sh address.
    def non_reissuable(out_point, address, value)
      color_id = Tapyrus::Color::ColorIdentifier.non_reissuable(out_point)
      pay(address, value, color_id)
    end

    # Issue NFT
    # @param address [String] p2pkh or p2sh address.
    def nft(out_point, address)
      color_id = Tapyrus::Color::ColorIdentifier.nft(out_point)
      pay(address, 1, color_id)
    end

    # Create payment output.
    # @param address [String] tapyrus address with Base58 format
    # @param value [Integer]
    # @param color_id [Tapyrus::Color::ColorIdentifier]
    def pay(address, value, color_id = Tapyrus::Color::ColorIdentifier::default)
      script_pubkey = Tapyrus::Script.parse_from_addr(address)

      unless color_id.default?
        raise ArgumentError, 'invalid address' if !script_pubkey.p2pkh? && !script_pubkey.p2sh?
        script_pubkey = script_pubkey.add_color(color_id)
      end

      @outgoings[color_id] ||= 0
      @outgoings[color_id] += value
      @tx.outputs << Tapyrus::TxOut.new(script_pubkey: script_pubkey, value: value)
      self
    end

    # Create data output
    # @param contents [[String]] array of hex string
    def data(*contents)
      payload = contents.inject('') do |payload, content|
        payload << content
      end
      script = Tapyrus::Script.new << Tapyrus::Script::OP_RETURN << payload
      @tx.outputs << Tapyrus::TxOut.new(script_pubkey: script)
      self
    end

    # Set transaction fee.
    # @param fee [Integer] transaction fee
    def fee(fee)
      @fee = fee
      self
    end

    # Set script_pubkey for change.
    # If set, #build method add output for change which has the specified script_pubkey
    # If not set, transaction built by #build method has no output for change.
    # @param script_pubkey [Tapyrus::Script] p2pkh or p2sh
    def change_script_pubkey(script_pubkey)
      raise ArgumentError, 'invalid address' if !script_pubkey.p2pkh? && !script_pubkey.p2sh?
      @change_script_pubkey = script_pubkey
      self
    end

    # Build transaction
    def build
      expand_input
      add_change if @change_script_pubkey
      @tx
    end

    private

    def add_change
      @incomings.each do |color_id, in_amount|
        out_amount = @outgoings[color_id] || 0
        change, script_pubkey = if color_id.default?
          [in_amount - out_amount - estimated_fee, @change_script_pubkey]
        else
          [in_amount - out_amount, @change_script_pubkey.add_color(color_id)]
        end
        @tx.outputs << Tapyrus::TxOut.new(script_pubkey: script_pubkey, value: change) if change > 0
      end
    end

    def expand_input
      @utxos.each do |utxo|
        @tx.inputs << Tapyrus::TxIn.new(out_point: Tapyrus::OutPoint.from_txid(utxo[:txid], utxo[:index]))
      end
    end

    # Return transaction fee
    def estimated_fee
      @fee
    end
  end
end
