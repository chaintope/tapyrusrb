require "uri"

module Tapyrus
  module TIP0020
    # Token metadata class based on TIP-0020 specification
    # @see https://github.com/chaintope/tips/blob/main/tip-0020.md
    class Metadata
      CURRENT_VERSION = "1.0"
      MAX_NAME_LENGTH = 64
      MAX_SYMBOL_LENGTH = 12
      MAX_DESCRIPTION_LENGTH = 256
      MIN_DECIMALS = 0
      MAX_DECIMALS = 18
      MAX_DATA_URI_SIZE = 32 * 1024 # 32KB

      VALID_TOKEN_TYPES = %i[reissuable non_reissuable nft].freeze
      NFT_FIELDS = %i[image animation_url external_url attributes].freeze

      attr_accessor :token_type,
                    :version,
                    :name,
                    :symbol,
                    :decimals,
                    :description,
                    :icon,
                    :issuer,
                    :website,
                    :terms,
                    :properties,
                    :image,
                    :animation_url,
                    :external_url,
                    :attributes

      # @param token_type [Symbol] Token type (:reissuable, :non_reissuable, :nft)
      # @param version [String] Schema version (default: "1.0")
      # @param name [String] Human-readable token name (max 64 characters, required)
      # @param symbol [String] Token symbol (max 12 characters, required)
      # @param decimals [Integer] Number of decimal places for display (0-18, default: 0)
      # @param description [String] Token description (max 256 characters)
      # @param icon [String] HTTPS URL or Data URI for icon
      # @param issuer [Hash] Issuer information object
      # @param website [String] Official website URL (HTTPS required)
      # @param terms [String] URL to terms of service document (HTTPS required)
      # @param properties [Hash] Additional custom properties
      # @param image [String] NFT image URL (HTTPS or Data URI) - only for NFT
      # @param animation_url [String] NFT animation/video/audio URL (HTTPS or Data URI) - only for NFT
      # @param external_url [String] External URL to view NFT (HTTPS required) - only for NFT
      # @param attributes [Array<Hash>] NFT attributes array with trait_type, value, display_type - only for NFT
      def initialize(
        token_type:,
        version: CURRENT_VERSION,
        name:,
        symbol:,
        decimals: 0,
        description: nil,
        icon: nil,
        issuer: nil,
        website: nil,
        terms: nil,
        properties: nil,
        image: nil,
        animation_url: nil,
        external_url: nil,
        attributes: nil
      )
        @token_type = token_type
        @version = version
        @name = name
        @symbol = symbol
        @decimals = decimals
        @description = description
        @icon = icon
        @issuer = issuer
        @website = website
        @terms = terms
        @properties = properties
        @image = image
        @animation_url = animation_url
        @external_url = external_url
        @attributes = attributes
        validate!
      end

      # Validate metadata fields
      # @raise [ArgumentError] if validation fails
      def validate!
        raise ArgumentError, "token_type is required" if token_type.nil?
        unless VALID_TOKEN_TYPES.include?(token_type)
          raise ArgumentError, "token_type must be one of #{VALID_TOKEN_TYPES.join(", ")}"
        end
        validate_nft_fields!
        raise ArgumentError, "version is required" if version.nil? || version.empty?
        raise ArgumentError, "version must be #{CURRENT_VERSION}" unless version == CURRENT_VERSION
        raise ArgumentError, "name is required" if name.nil? || name.empty?
        raise ArgumentError, "name must be #{MAX_NAME_LENGTH} characters or less" if name.length > MAX_NAME_LENGTH
        raise ArgumentError, "symbol is required" if symbol.nil? || symbol.empty?
        if symbol.length > MAX_SYMBOL_LENGTH
          raise ArgumentError, "symbol must be #{MAX_SYMBOL_LENGTH} characters or less"
        end
        if decimals < MIN_DECIMALS || decimals > MAX_DECIMALS
          raise ArgumentError, "decimals must be between #{MIN_DECIMALS} and #{MAX_DECIMALS}"
        end
        if description && description.length > MAX_DESCRIPTION_LENGTH
          raise ArgumentError, "description must be #{MAX_DESCRIPTION_LENGTH} characters or less"
        end
        raise ArgumentError, "icon must be an HTTPS URL or Data URI" if icon && !valid_icon_format?(icon)
        raise ArgumentError, "website must be an HTTPS URL" if website && !valid_https_url?(website)
        raise ArgumentError, "terms must be an HTTPS URL" if terms && !valid_https_url?(terms)
        raise ArgumentError, "image must be an HTTPS URL or Data URI" if image && !valid_media_url?(image)
        if animation_url && !valid_media_url?(animation_url)
          raise ArgumentError, "animation_url must be an HTTPS URL or Data URI"
        end
        raise ArgumentError, "external_url must be an HTTPS URL" if external_url && !valid_https_url?(external_url)
        validate_issuer! if issuer
      end

      # Validate issuer object fields
      # @raise [ArgumentError] if validation fails
      def validate_issuer!
        return unless issuer.is_a?(Hash)
        issuer_url = issuer[:url] || issuer["url"]
        raise ArgumentError, "issuer.url must be an HTTPS URL" if issuer_url && !valid_https_url?(issuer_url)
        issuer_email = issuer[:email] || issuer["email"]
        raise ArgumentError, "issuer.email must be a valid email address" if issuer_email && !valid_email?(issuer_email)
      end

      # Validate NFT-specific fields are only used with NFT token type
      # @raise [ArgumentError] if NFT fields are used with non-NFT token type
      def validate_nft_fields!
        return if token_type == :nft
        nft_fields_present = NFT_FIELDS.select { |field| send(field) }
        unless nft_fields_present.empty?
          raise ArgumentError, "#{nft_fields_present.join(", ")} can only be used with NFT token type"
        end
      end

      # Convert to Hash
      # @return [Hash] metadata as hash
      def to_h
        result = { version: version, name: name, symbol: symbol }
        result[:decimals] = decimals if decimals != 0
        result[:description] = description if description
        result[:icon] = icon if icon
        result[:issuer] = issuer if issuer
        result[:website] = website if website
        result[:terms] = terms if terms
        result[:properties] = properties if properties
        # NFT fields
        result[:image] = image if image
        result[:animation_url] = animation_url if animation_url
        result[:external_url] = external_url if external_url
        result[:attributes] = attributes if attributes
        result
      end

      # Canonicalize metadata according to RFC 8785 (JCS)
      # @return [String] canonicalized JSON string
      def canonicalize
        jcs_serialize(to_h)
      end

      # Calculate SHA256 hash of canonicalized metadata
      # @return [String] 32-byte binary hash
      def digest
        Tapyrus.sha256(canonicalize)
      end

      # Calculate SHA256 hash and return as hex string
      # @return [String] 64-character hex string
      def digest_hex
        digest.bth
      end

      # Calculate P2C commitment: c = SHA256(P || h)
      # @param pubkey [String] payment base public key (33 bytes compressed, hex string)
      # @return [String] 32-byte binary commitment
      def commitment(pubkey)
        pubkey_bin = pubkey.htb
        raise ArgumentError, "pubkey must be 33 bytes compressed public key" unless pubkey_bin.bytesize == 33
        Tapyrus.sha256(pubkey_bin + digest)
      end

      # Calculate P2C commitment and return as hex string
      # @param pubkey [String] payment base public key (33 bytes compressed, hex string)
      # @return [String] 64-character hex string
      def commitment_hex(pubkey)
        commitment(pubkey).bth
      end

      # Derive P2C public key: P' = P + c * G
      # @param pubkey [String] payment base public key (33 bytes compressed, hex string)
      # @return [String] P2C public key (33 bytes compressed, hex string)
      # @raise [ArgumentError] if derivation results in point at infinity
      def derive_p2c_pubkey(pubkey)
        c = commitment(pubkey)
        c_int = c.bth.to_i(16)

        # P + c * G
        group = ECDSA::Group::Secp256k1
        point_p = Tapyrus::Key.new(pubkey: pubkey).to_point
        point_cg = group.generator * c_int
        point_p_prime = point_p + point_cg

        raise ArgumentError, "P2C derivation resulted in point at infinity" if point_p_prime.infinity?

        # Compress the result
        ECDSA::Format::PointOctetString.encode(point_p_prime, compression: true).bth
      end

      # Derive P2C address
      # @param pubkey [String] payment base public key (33 bytes compressed, hex string)
      # @return [String] P2C address
      def derive_p2c_address(pubkey)
        p2c_pubkey = derive_p2c_pubkey(pubkey)
        Tapyrus::Key.new(pubkey: p2c_pubkey).to_p2pkh
      end

      # Create ColorIdentifier based on token type
      # @param pubkey [String] payment base public key (33 bytes compressed, hex string) - required for :reissuable
      # @param out_point [Tapyrus::OutPoint] out point - required for :non_reissuable and :nft
      # @return [Tapyrus::Color::ColorIdentifier] color identifier
      def derive_color_id(pubkey: nil, out_point: nil)
        case token_type
        when :reissuable
          raise ArgumentError, "pubkey is required for reissuable token" unless pubkey
          p2c_pubkey = derive_p2c_pubkey(pubkey)
          script = Tapyrus::Script.to_p2pkh(Tapyrus::Key.new(pubkey: p2c_pubkey).hash160)
          Tapyrus::Color::ColorIdentifier.reissuable(script)
        when :non_reissuable
          raise ArgumentError, "out_point is required for non_reissuable token" unless out_point
          Tapyrus::Color::ColorIdentifier.non_reissuable(out_point)
        when :nft
          raise ArgumentError, "out_point is required for nft token" unless out_point
          Tapyrus::Color::ColorIdentifier.nft(out_point)
        end
      end

      # Parse from JSON string
      # @param json_str [String] JSON string
      # @param token_type [Symbol] Token type (:reissuable, :non_reissuable, :nft)
      # @return [Metadata] metadata instance
      def self.parse(json_str, token_type:)
        data = JSON.parse(json_str, symbolize_names: true)
        new(
          token_type: token_type,
          version: data[:version] || CURRENT_VERSION,
          name: data[:name],
          symbol: data[:symbol],
          decimals: data[:decimals] || 0,
          description: data[:description],
          icon: data[:icon],
          issuer: data[:issuer],
          website: data[:website],
          terms: data[:terms],
          properties: data[:properties],
          image: data[:image],
          animation_url: data[:animation_url],
          external_url: data[:external_url],
          attributes: data[:attributes]
        )
      end

      private

      # Check if the URL is a valid HTTPS URL
      def valid_https_url?(url)
        uri = URI.parse(url)
        uri.is_a?(URI::HTTPS)
      rescue URI::InvalidURIError
        false
      end

      # Check if the icon format is valid (HTTPS URL or Data URI)
      def valid_icon_format?(icon)
        valid_media_url?(icon)
      end

      # Check if media URL is valid (HTTPS URL or Data URI with size limit)
      def valid_media_url?(url)
        return url.bytesize <= MAX_DATA_URI_SIZE if url.start_with?("data:")
        valid_https_url?(url)
      end

      # Check if email format is valid
      def valid_email?(email)
        # Basic email format validation
        email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end

      # RFC 8785 JSON Canonicalization Scheme serialization
      # @param obj [Object] object to serialize
      # @return [String] canonicalized JSON string
      def jcs_serialize(obj)
        case obj
        when Hash
          pairs =
            obj
              .keys
              .map(&:to_s)
              .sort
              .map { |key| "#{jcs_serialize(key)}:#{jcs_serialize(obj[key.to_sym] || obj[key])}" }
          "{#{pairs.join(",")}}"
        when Array
          "[#{obj.map { |v| jcs_serialize(v) }.join(",")}]"
        when String
          JSON.generate(obj)
        when Integer
          obj.to_s
        when Float
          # RFC 8785 requires specific float formatting
          jcs_format_float(obj)
        when TrueClass, FalseClass
          obj.to_s
        when NilClass
          "null"
        else
          JSON.generate(obj)
        end
      end

      # Format float according to RFC 8785
      def jcs_format_float(num)
        return "0" if num.zero?
        return "null" if num.nan? || num.infinite?

        # Use exponential notation for very large or very small numbers
        if num.abs >= 1e21 || (num != 0 && num.abs < 1e-6)
          # Exponential format
          exp = Math.log10(num.abs).floor
          mantissa = num / (10**exp)
          "#{mantissa}e#{exp >= 0 ? "+" : ""}#{exp}"
        else
          # Remove trailing zeros
          str = num.to_s
          str.sub(/\.?0+$/, "")
        end
      end
    end
  end
end
