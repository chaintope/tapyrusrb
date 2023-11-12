module Tapyrus
  module TIP0002
    # @param key [Tapyrus::Key] private key
    # @param txid [String] txid
    # @param index [Integer] index of transaction output
    # @param color_id [Tapyrus::Color::ColorIdentifier] a valid color id
    # @param value [Integer] non-negative integer less than 2^64
    # @param script_pubkey [Tapyrus::Script] script pubkey in transaction output
    # @param address [String] Tapyrus address for transaction output
    # @param data [String] hexdecimal string
    # @param client [Tapyrus::RPC::TapyrusCoreClient] rpc client
    def sign_message(key, txid:, index:, color_id:, value:, script_pubkey:, address:, data: nil, client: nil)
      validate_payload!(txid:, index:, color_id:, value:, script_pubkey:, address:, data:)
      validate_on_blockchain!(client:, txid:, index:, color_id:, value:, script_pubkey:)
      data = {
        txid:,index:, color_id: color_id&.to_hex, value:, script_pubkey: script_pubkey&.to_hex, address:, data:
      }
      JWS.encode(data, key.priv_key)
    end

    # @param jws [String] JWT Web Token
    # @param key [Tapyrus::Key] public key
    # @param client [Tapyrus::RPC::TapyrusCoreClient] rpc client
    # @return decoded JSON Object
    def verify_message(jws, key, client: nil)
      JWS.decode(jws, key.pubkey).tap do |decoded|
        payload = decoded[0]
        color_id = begin
          Tapyrus::Color::ColorIdentifier.parse_from_payload(payload["color_id"]&.htb)
        rescue => _e
          raise RuntimeError, "color_id is invalid" 
        end
        script_pubkey = begin
          Tapyrus::Script.parse_from_payload(payload["script_pubkey"]&.htb)
        rescue => _e
          raise RuntimeError, "script_pubkey is invalid"
        end

        validate_payload!(txid: payload["txid"], index: payload["index"], color_id: color_id, value: payload["value"], script_pubkey: script_pubkey, address: payload["address"], data: payload["data"])
        validate_on_blockchain!(client:, txid: payload["txid"], index: payload["index"], color_id: color_id, value: payload["value"], script_pubkey: script_pubkey) if client
      end
    end

    def validate_payload!(txid:, index:, color_id:, value:, script_pubkey:, address:, data:)
      if !txid || !/^[0-9a-fA-F]{64}$/.match(txid)
        raise RuntimeError, "txid is invalid" 
      end

      if !index || !/^\d+$/.match(index.to_s) || index < 0 || index >= 2**32
        raise RuntimeError, "index is invalid" 
      end

      if !color_id || !color_id.is_a?(Tapyrus::Color::ColorIdentifier) || !color_id.valid?
        raise RuntimeError, "color_id is invalid" 
      end

      if !value || !/^\d+$/.match(value.to_s) || value < 0 || value >= 2**64
        raise RuntimeError, "value is invalid" 
      end

      if !script_pubkey || !script_pubkey.is_a?(Tapyrus::Script) || !/^([0-9a-fA-F]{2})+$/.match(script_pubkey.to_hex)
        raise RuntimeError, "script_pubkey is invalid"
      end

      begin
        address && Base58.decode(address)
      rescue ArgumentError => e
        raise RuntimeError, "address is invalid" 
      end

      if data && !/^([0-9a-fA-F]{2})+$/.match(data)
        raise RuntimeError, "data is invalid" 
      end
    end

    def validate_on_blockchain!(client:, txid:, index:, color_id:, value:, script_pubkey:)
      raw_tx = client.getrawtransaction(txid)
      tx = Tapyrus::Tx.parse_from_payload(raw_tx.htb)
      output = tx.outputs[index]
      unless output
        raise RuntimeError, "output not found in blockchain"
      end

      if color_id != output.color_id
        raise RuntimeError, "color_id of transaction in blockchain is not match to one in the signed message"
      end

      if value != output.value
        raise RuntimeError, "value of transaction in blockchain is not match to one in the signed message"
      end

      if script_pubkey != output.script_pubkey
        raise RuntimeError, "script_pubkey of transaction in blockchain is not match to one in the signed message"
      end
    end
  end
end
