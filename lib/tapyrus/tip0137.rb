module Tapyrus
  module TIP0137
    # @param key [Tapyrus::Key] private key
    # @param txid [String] txid
    # @param index [Integer] index of transaction output
    # @param color_id [Tapyrus::Color::ColorIdentifier] a valid color id
    # @param value [Integer] non-negative integer less than 2^64
    # @param script_pubkey [Tapyrus::Script] script pubkey in transaction output
    # @param address [String] Tapyrus address for transaction output
    # @param data [String] hexdecimal string
    # @param client [Tapyrus::RPC::TapyrusCoreClient] rpc client
    # @return [String] Signed message with JWS Format
    # @raise [ArgumentError] raise if txid is not a 64-character hexadecimal string
    # @raise [ArgumentError] raise if index is not a non-negative integer less than 2^32
    # @raise [ArgumentError] raise if color_id is an invalid Tapyrus::Color::ColorIdentifier object
    # @raise [ArgumentError] raise if value is not a non-negative integer less than 2^64
    # @raise [ArgumentError] raise if script_pubkey is an invalid Tapyrus::Script object
    # @raise [ArgumentError] raise if address is an invalid Tapyrus address
    # @raise [ArgumentError] raise if data is not a hexdecimal string
    # @raise [ArgumentError] raise if transaction is not found with txid and index in blockchain 
    # @raise [ArgumentError] raise if script and value is not equal to ones in blockchain
    def sign_message!(
      key,
      txid:,
      index:,
      value: ,
      script_pubkey:,
      color_id: nil,
      address: nil,
      data: nil,
      client: nil
    )
      validate_payload!(
        txid: txid,
        index: index,
        color_id: color_id,
        value: value,
        script_pubkey: script_pubkey,
        address: address,
        data: data
      )
      if client
        validate_on_blockchain!(
          client: client,
          txid: txid,
          index: index,
          color_id: color_id,
          value: value,
          script_pubkey: script_pubkey
        )
      end
      data = {
        txid: txid,
        index: index,
        color_id: color_id&.to_hex,
        value: value,
        script_pubkey: script_pubkey&.to_hex,
        address: address,
        data: data
      }
      JWS.encode(data, key.priv_key)
    end

    # @param jws [String] JWT Web Token
    # @param key [Tapyrus::Key] public key
    # @param client [Tapyrus::RPC::TapyrusCoreClient] rpc client
    # @return decoded JSON Object
    # @raise [ArgumentError] raise if decoded txid is not a 64-character hexadecimal string
    # @raise [ArgumentError] raise if decoded index is not a non-negative integer less than 2^32
    # @raise [ArgumentError] raise if decoded color_id is an invalid Tapyrus::Color::ColorIdentifier object
    # @raise [ArgumentError] raise if decoded value is not a non-negative integer less than 2^64
    # @raise [ArgumentError] raise if decoded script_pubkey is an invalid Tapyrus::Script object
    # @raise [ArgumentError] raise if decoded address is an invalid Tapyrus address
    # @raise [ArgumentError] raise if decoded data is not a hexdecimal string
    # @raise [ArgumentError] raise if transaction is not found with decoded txid and index in blockchain 
    # @raise [ArgumentError] raise if decoded script and value is not equal to ones in blockchain
    def verify_message!(jws, key, client: nil)
      JWS
        .decode(jws, key.pubkey)
        .tap do |decoded|
          payload = decoded[0]
          color_id =
            begin
              Tapyrus::Color::ColorIdentifier.parse_from_payload(payload['color_id']&.htb) if payload['color_id']
            rescue => _e
              raise ArgumentError, 'color_id is invalid'
            end
          script_pubkey =
            begin
              Tapyrus::Script.parse_from_payload(payload['script_pubkey']&.htb)
            rescue => _e
              raise ArgumentError, 'script_pubkey is invalid'
            end
          validate_payload!(
            txid: payload['txid'],
            index: payload['index'],
            color_id: color_id,
            value: payload['value'],
            script_pubkey: script_pubkey,
            address: payload['address'],
            data: payload['data']
          )
          if client
            validate_on_blockchain!(
              client: client,
              txid: payload['txid'],
              index: payload['index'],
              color_id: color_id,
              value: payload['value'],
              script_pubkey: script_pubkey
            )
          end
        end
    end

    # @param jws [String] JWT Web Token
    # @param key [Tapyrus::Key] public key
    # @param client [Tapyrus::RPC::TapyrusCoreClient] rpc client
    # @return [Boolean] true if JWT and decoded object is valid.
    def verify_message(jws, key, client: nil)
      verify_message!(jws, key, client: client)
      true
    rescue ArgumentError, JWT::VerificationError
      return false
    end

    def validate_payload!(txid:, index:, value:, script_pubkey:, color_id: nil, address: nil, message: nil)
      raise ArgumentError, 'txid is invalid' if !txid || !/^[0-9a-fA-F]{64}$/.match(txid)
      raise ArgumentError, 'index is invalid' if !index || !/^\d+$/.match(index.to_s) || index < 0 || index >= 2**32
      if color_id && (!color_id.is_a?(Tapyrus::Color::ColorIdentifier) || !color_id.valid?)
        raise ArgumentError, 'color_id is invalid'
      end
      raise ArgumentError, 'value is invalid' if !value || !/^\d+$/.match(value.to_s) || value < 0 || value >= 2**64
      if !script_pubkey || !script_pubkey.is_a?(Tapyrus::Script)
        raise ArgumentError, 'script_pubkey is invalid'
      end
      begin
        address && Base58.decode(address)
      rescue ArgumentError => e
        raise ArgumentError, 'address is invalid'
      end
      raise ArgumentError, 'data is invalid' if data && !/^([0-9a-fA-F]{2})+$/.match(data)
    end

    def validate_on_blockchain!(client: nil, txid: nil, index: nil, color_id: nil, value: nil, script_pubkey: nil)
      raw_tx = client.getrawtransaction(txid)
      tx = Tapyrus::Tx.parse_from_payload(raw_tx.htb)
      output = tx.outputs[index]
      raise ArgumentError, 'output not found in blockchain' unless output
      if color_id != output.color_id
        raise ArgumentError, 'color_id of transaction in blockchain is not match to one in the signed message'
      end
      if value != output.value
        raise ArgumentError, 'value of transaction in blockchain is not match to one in the signed message'
      end
      if script_pubkey != output.script_pubkey
        raise ArgumentError, 'script_pubkey of transaction in blockchain is not match to one in the signed message'
      end
    end
  end
end
