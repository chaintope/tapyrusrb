# frozen_string_literal: true

module OpenAssets
  module Util
    class << self
      OA_VERSION_BYTE = '17' # 0x23
      OA_VERSION_BYTE_TESTNET = '73' # 0x115

      def script_to_asset_id(script)
        hash_to_asset_id(Tapyrus.hash160(script))
      end

      private

      def hash_to_asset_id(hash)
        hash = oa_version_byte + hash
        Tapyrus::Base58.encode(hash + Tapyrus.calc_checksum(hash))
      end

      def oa_version_byte
        return OA_VERSION_BYTE if Tapyrus.chain_params.prod?
        return OA_VERSION_BYTE_TESTNET if Tapyrus.chain_params.dev?
      end
    end
  end
end
