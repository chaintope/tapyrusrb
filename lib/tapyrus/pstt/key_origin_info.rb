module Tapyrus
  module PSTT
    # The value of a BIP 32 derivation record: a master key fingerprint followed by a derivation path.
    class KeyOriginInfo
      include Tapyrus::KeyPath
      extend Tapyrus::KeyPath

      # @!attribute [r] fingerprint
      #   @return [String] the master key fingerprint with hex format.
      attr_reader :fingerprint

      # @!attribute [r] key_paths
      #   @return [Array[Integer]] the derivation path as a sequence of 32-bit unsigned integers.
      attr_reader :key_paths

      # @param [String] fingerprint the master key fingerprint with hex format.
      # @param [Array[Integer]] key_paths the derivation path.
      def initialize(fingerprint:, key_paths: [])
        raise Error, "fingerprint must be 4 bytes." unless fingerprint.htb.bytesize == 4
        @fingerprint = fingerprint
        @key_paths = key_paths
      end

      # Parse the value of a BIP 32 derivation record.
      # @param [String] payload the value with binary format.
      # @return [Tapyrus::PSTT::KeyOriginInfo]
      def self.parse_from_payload(payload)
        if payload.bytesize < 4 || ((payload.bytesize - 4) % 4) != 0
          raise Error, "BIP 32 derivation value must be a 4-byte fingerprint followed by 32-bit path elements."
        end
        fingerprint, *key_paths = payload.unpack("H8V*")
        new(fingerprint: fingerprint, key_paths: key_paths)
      end

      # Build from a derivation path string such as "m/44'/2377'/0'/0/0".
      # @param [String] fingerprint the master key fingerprint with hex format.
      # @param [String] path the derivation path string.
      # @return [Tapyrus::PSTT::KeyOriginInfo]
      def self.from_path(fingerprint, path)
        new(fingerprint: fingerprint, key_paths: parse_key_path(path))
      end

      def to_payload
        fingerprint.htb + key_paths.pack("V*")
      end

      # @return [String] the derivation path string.
      def path
        to_key_path(key_paths)
      end

      def ==(other)
        other.is_a?(KeyOriginInfo) && to_payload == other.to_payload
      end
    end
  end
end
