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
    def sign_message(key, txid:, index:, color_id:, value:, script_pubkey:, address:, data: nil)
      validate_payload!(txid:, index:, color_id:, value:, script_pubkey:, address:, data:)
      data = {
        txid:,index:, color_id: color_id&.to_hex, value:, script_pubkey: script_pubkey&.to_hex, address:, data:
      }
      JWS.encode(data, key.priv_key)
    end

    # @param jws [String] JWT Web Token
    # @param key [Tapyrus::Key] public key
    # @return decoded JSON Object
    def verify_message(jws, key)
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
  end
end
