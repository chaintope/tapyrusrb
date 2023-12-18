module Tapyrus
  module TIP0137
    # @param key [Tapyrus::Key] A private key
    # @param txid [String] A transaction id string in hexadecimal format (64 characters long)
    # @param index [Integer] Index of the transaction output, a non-negative integer less than 2^32
    # @param color_id [Tapyrus::Color::ColorIdentifier] A valid instance of Tapyrus::Color::ColorIdentifier
    # @param value [Integer] A non-negative integer less than 2^64 representing the value of the transaction output
    # @param script_pubkey [Tapyrus::Script] A script pubkey in the transaction output
    # @param address [String] A valid Tapyrus address string for the transaction output
    # @param message [String] A hexadecimal formatted string
    # @param client [Tapyrus::RPC::TapyrusCoreClient] The RPC client instance. If the client is specified, verify that the transaction associated with the txid and index exists on the blockchain and that a valid script_pubkey exists in the transaction.
    # @return [String] Returns the message signed in JWS Format
    # @raise [ArgumentError] If the txid is not a 64-character hexadecimal string
    # @raise [ArgumentError] If the index is not a non-negative integer less than 2^32
    # @raise [ArgumentError] If the color_id is not a valid Tapyrus::Color::ColorIdentifier object
    # @raise [ArgumentError] If the value is not a non-negative integer less than 2^64
    # @raise [ArgumentError] If the script_pubkey is not a valid Tapyrus::Script object
    # @raise [ArgumentError] If the provided Tapyrus address is invalid
    # @raise [ArgumentError] If the message is not a hexadecimal string
    # @raise [ArgumentError] If the transaction with the given txid and index is not found in the blockchain
    # @raise [ArgumentError] If the script and value do not correspond with those in the blockchain
    # @raise [Tapyrus::RPC::Error] If RPC access fails
    def sign_message!(
      key,
      txid:,
      index:,
      value:,
      script_pubkey:,
      color_id: nil,
      address: nil,
      message: nil,
      client: nil
    )
      validate_payload!(
        key: key,
        txid: txid,
        index: index,
        color_id: color_id,
        value: value,
        script_pubkey: script_pubkey,
        address: address,
        message: message
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
        message: message
      }
      Tapyrus::JWS.encode(data, key.priv_key)
    end

    # @param jws [String] JWS (JSON Web Signature)
    # @param client [Tapyrus::RPC::TapyrusCoreClient] The RPC client instance. If the client is specified, verify that the transaction associated with the txid and index exists on the blockchain and that a valid script_pubkey exists in the transaction.
    # @return A decoded JSON Object
    # @raise [ArgumentError] If the decoded txid is not a 64-character hexadecimal string
    # @raise [ArgumentError] If the decoded index is not a non-negative integer less than 2^32
    # @raise [ArgumentError] If the decoded color_id is an invalid Tapyrus::Color::ColorIdentifier object
    # @raise [ArgumentError] If the decoded value is not a non-negative integer less than 2^64
    # @raise [ArgumentError] If the decoded script_pubkey is an invalid Tapyrus::Script object
    # @raise [ArgumentError] If the decoded address is an invalid Tapyrus address
    # @raise [ArgumentError] If the decoded message is not a hexadecimal string
    # @raise [ArgumentError] If a transaction is not found with the decoded txid and index in the blockchain
    # @raise [ArgumentError] If the decoded script and value do not match the ones in the blockchain
    # @raise [JWT::DecodeError] If JWS decoding fails
    # @raise [Tapyus::JWS::DecodeError] If the JWK key is invalid
    # @raise [JWT::VerificationError] If the verification of the signature fails
    # @raise [Tapyrus::RPC::Error] If RPC access fails
    def verify_message!(jws, client: nil)
      Tapyrus::JWS
        .decode(jws)
        .tap do |decoded|
          header = decoded[1]
          validate_header!(header)
          jwk = header.dig('jwk', 'keys', 0)
          key = to_tapyrus_key(jwk)
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
            key: key,
            txid: payload['txid'],
            index: payload['index'],
            color_id: color_id,
            value: payload['value'],
            script_pubkey: script_pubkey,
            address: payload['address'],
            message: payload['message']
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

    # @param jws [String] JWS (JSON Web Signature)
    # @param client [Tapyrus::RPC::TapyrusCoreClient]  The RPC client instance
    # @return [Boolean] true if JWT and decoded object is valid.
    def verify_message(jws, client: nil)
      verify_message!(jws, client: client)
      true
    rescue ArgumentError, JWT::DecodeError, JWT::VerificationError
      return false
    end

    def validate_header!(header)
      raise ArgumentError, 'type must be "JWT"' if header['typ'] && header['typ'] != 'JWT'
      raise ArgumentError, 'alg must be "ES256K"' if header['alg'] && header['alg'] != Tapyrus::JWS::ALGO
    end

    def validate_payload!(key:, txid:, index:, value:, script_pubkey:, color_id: nil, address: nil, message: nil)
      raise ArgumentError, 'txid is invalid' if !txid || !/^[0-9a-fA-F]{64}$/.match(txid)
      raise ArgumentError, 'index is invalid' if !index || !/^\d+$/.match(index.to_s) || index < 0 || index >= 2**32

      raise ArgumentError, 'value is invalid' if !value || !/^\d+$/.match(value.to_s) || value < 0 || value >= 2**64
      if !script_pubkey || !script_pubkey.is_a?(Tapyrus::Script) || !(script_pubkey.p2pkh? || script_pubkey.cp2pkh?)
        raise ArgumentError,
              'script_pubkey is invalid. scirpt_pubkey must be a hex string and its type must be p2pkh or cp2pkh'
      end

      if color_id
        if !color_id.is_a?(Tapyrus::Color::ColorIdentifier) || !color_id.valid?
          raise ArgumentError, 'color_id is invalid'
        end

        raise ArgumentError, 'color_id should be equal to colorId in scriptPubkey' if color_id != script_pubkey.color_id
      end

      begin
        address && Base58.decode(address)
      rescue ArgumentError => e
        raise ArgumentError, 'address is invalid'
      end

      if address && script_pubkey.to_addr != address
        raise ArgumentError, 'address is invalid. An address should be derived from scriptPubkey'
      end

      if (script_pubkey.p2pkh? && key.to_p2pkh != script_pubkey.to_addr) ||
           (script_pubkey.cp2pkh? && key.to_p2pkh != script_pubkey.remove_color.to_addr)
        raise ArgumentError, 'key is invalid'
      end

      if message && !/^([0-9a-fA-F]{2})+$/.match(message)
        raise ArgumentError, 'message is invalid. message must be a hex string'
      end
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

    def to_tapyrus_key(jwk)
      vefiry_key = JWT::JWK.new(jwk).verify_key
      pubkey = vefiry_key.public_key.to_octet_string(:compressed)
      Tapyrus::Key.new(pubkey: pubkey.bth)
    end
  end
end
