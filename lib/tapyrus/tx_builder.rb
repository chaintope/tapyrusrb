module Tapyrus
  #
  # Transaction Builder class.
  #
  # TxBuilder makes it easy to  build transactions without having to deal with TxOut/TxIn/Script directly.
  #
  # @example
  # 
  #   txb = Tapyrus::TxBuilder.new
  #   utxo1 = {
  #     script_pubkey: Tapyrus::Script.parse_from_addr('mgCuyNQ1pUbKqL57tJQZX3hhUCaZcuX3RQ'),
  #     txid: 'e1fb3255ead43dccd3ae0ac2c4f81b32260ca52749936a739669918bbb895411',
  #     index: 0,
  #     value: 3_000
  #   }
  #   color_id = Tapyrus::Color::ColorIdentifier.nft(...)
  #   utxo2 = {
  #     script_pubkey: Tapyrus::Script.parse_from_addr('mu9QMUcB9UCHbQjZJLAuyysQhM9tmFQbPx'),
  #     color_id: color_id,
  #     txid: 'e1fb3255ead43dccd3ae0ac2c4f81b32260ca52749936a739669918bbb895411',
  #     index: 1,
  #     value: 3_000
  #   }
  #   
  #   tx = txb
  #     .add_utxo(utxo1)
  #     .add_utxo(utxo2)
  #     .data("0102030405060a0b0c")
  #     .reissuable(utxo1[:script_pubkey],'n4jKJN5UMLsAejL1M5CTzQ8npeWoLBLCAH', 10_000)
  #     .pay('n4jKJN5UMLsAejL1M5CTzQ8npeWoLBLCAH', 1_000)
  #     .build
  # 
  class TxBuilder
    def initialize
      @utxos = []
      @incomings = {}
      @outgoings = {}
      @outputs = []
    end

    # Add utxo for transaction input
    # @param utxo [Hash] a hash whose fields are `txid`, `index`, `script_pubkey`, `value`, and `color_id` (color_id is optional)
    def add_utxo(utxo)
      @utxos << utxo
      color_id = utxo[:color_id] || Tapyrus::Color::ColorIdentifier::default
      @incomings[color_id] ||= 0
      @incomings[color_id] += utxo[:value]
      self
    end

    # Issue reissuable token
    # @param script_pubkey [Tapyrus::Script] the script pubkey in the issue input.
    # @param address [String] p2pkh or p2sh address.
    # @param value [Integer] issued amount.
    def reissuable(script_pubkey, address, value)
      color_id = Tapyrus::Color::ColorIdentifier.reissuable(script_pubkey)
      pay(address, value, color_id)
    end

    # Issue non reissuable token
    # @param out_point [Tapyrus::OutPoint] the out point at issue input.
    # @param address [String] p2pkh or p2sh address.
    # @param value [Integer] issued amount.
    def non_reissuable(out_point, address, value)
      color_id = Tapyrus::Color::ColorIdentifier.non_reissuable(out_point)
      pay(address, value, color_id)
    end

    # Issue NFT
    # @param out_point [Tapyrus::OutPoint] the out point at issue input.
    # @param address [String] p2pkh or p2sh address.
    # @param value [Integer] issued amount.
    def nft(out_point, address)
      color_id = Tapyrus::Color::ColorIdentifier.nft(out_point)
      pay(address, 1, color_id)
    end

    # Create payment output.
    # @param address [String] tapyrus address with Base58 format
    # @param value [Integer] issued or transferred amount
    # @param color_id [Tapyrus::Color::ColorIdentifier] color id
    def pay(address, value, color_id = Tapyrus::Color::ColorIdentifier::default)
      script_pubkey = Tapyrus::Script.parse_from_addr(address)

      unless color_id.default?
        raise ArgumentError, 'invalid address' if !script_pubkey.p2pkh? && !script_pubkey.p2sh?
        script_pubkey = script_pubkey.add_color(color_id)
      end

      @outgoings[color_id] ||= 0
      @outgoings[color_id] += value
      @outputs << Tapyrus::TxOut.new(script_pubkey: script_pubkey, value: value)
      self
    end

    # Create data output
    # @param contents [[String]] array of hex string
    def data(*contents)
      payload = contents.join
      script = Tapyrus::Script.new << Tapyrus::Script::OP_RETURN << payload
      @outputs << Tapyrus::TxOut.new(script_pubkey: script)
      self
    end

    # Set transaction fee.
    # @param fee [Integer] transaction fee
    def fee(fee)
      @fee = fee
      self
    end

    # Set address for change.
    # If set, #build method add output for change which has the specified address
    # If not set, transaction built by #build method has no output for change.
    # @param address [String] p2pkh or p2sh address.
    def change_address(address)
      script_pubkey = Tapyrus::Script.parse_from_addr(address)
      raise ArgumentError, 'invalid address' if !script_pubkey.p2pkh? && !script_pubkey.p2sh?
      @change_script_pubkey = script_pubkey
      self
    end

    # Build transaction
    def build
      tx = Tapyrus::Tx.new
      expand_input(tx)
      @outputs.each { |output| tx.outputs << output }
      add_change(tx) if @change_script_pubkey
      tx
    end

    private

    def add_change(tx)
      @incomings.each do |color_id, in_amount|
        out_amount = @outgoings[color_id] || 0
        change, script_pubkey = if color_id.default?
          [in_amount - out_amount - estimated_fee, @change_script_pubkey]
        else
          [in_amount - out_amount, @change_script_pubkey.add_color(color_id)]
        end
        tx.outputs << Tapyrus::TxOut.new(script_pubkey: script_pubkey, value: change) if change > 0
      end
    end

    def expand_input(tx)
      @utxos.each do |utxo|
        tx.inputs << Tapyrus::TxIn.new(out_point: Tapyrus::OutPoint.from_txid(utxo[:txid], utxo[:index]))
      end
    end

    # Return transaction fee
    def estimated_fee
      @fee
    end
  end
end
