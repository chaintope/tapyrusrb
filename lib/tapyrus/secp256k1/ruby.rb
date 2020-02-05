module Tapyrus
  module Secp256k1

    # secp256 module using ecdsa gem
    # https://github.com/DavidEGrayson/ruby_ecdsa
    module Ruby

      module_function

      # generate ec private key and public key
      def generate_key_pair(compressed: true)
        private_key = 1 + SecureRandom.random_number(GROUP.order - 1)
        public_key = GROUP.generator.multiply_by_scalar(private_key)
        privkey = ECDSA::Format::IntegerOctetString.encode(private_key, 32)
        pubkey = ECDSA::Format::PointOctetString.encode(public_key, compression: compressed)
        [privkey.bth, pubkey.bth]
      end

      # generate tapyrus key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Tapyrus::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      def generate_pubkey(privkey, compressed: true)
        public_key = ECDSA::Group::Secp256k1.generator.multiply_by_scalar(privkey.to_i(16))
        ECDSA::Format::PointOctetString.encode(public_key, compression: compressed).bth
      end

      # sign data.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign
      # @return [String] signature data with binary format
      def sign_data(data, privkey, extra_entropy)
        privkey = privkey.htb
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey)
        extra_entropy ||= ''
        nonce = RFC6979.generate_rfc6979_nonce(privkey + data, extra_entropy)

        # port form ecdsa gem.
        r_point = GROUP.new_point(nonce)

        point_field = ECDSA::PrimeField.new(GROUP.order)
        r = point_field.mod(r_point.x)
        return nil if r.zero?

        e = ECDSA.normalize_digest(data, GROUP.bit_length)
        s = point_field.mod(point_field.inverse(nonce) * (e + r * private_key))

        if s > (GROUP.order / 2) # convert low-s
          s = GROUP.order - s
        end

        return nil if s.zero?

        signature = ECDSA::Signature.new(r, s).to_der
        public_key = Tapyrus::Key.new(priv_key: privkey.bth).pubkey
        raise 'Creation of signature failed.' unless Tapyrus::Secp256k1::Ruby.verify_sig(data, signature, public_key)
        signature
      end

      # verify signature using public key
      # @param [String] digest a SHA-256 message digest with binary format
      # @param [String] sig a signature for +data+ with binary format
      # @param [String] pubkey a public key corresponding to the private key used for sign
      # @return [Boolean] verify result
      def verify_sig(digest, sig, pubkey)
        begin
          k = ECDSA::Format::PointOctetString.decode(repack_pubkey(pubkey), GROUP)
          signature = ECDSA::Format::SignatureDerString.decode(sig)
          ECDSA.valid_signature?(k, digest, signature)
        rescue Exception
          false
        end
      end

      alias :valid_sig? :verify_sig

      module_function :valid_sig?

      # if +pubkey+ is hybrid public key format, it convert uncompressed format.
      # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2012-June/001578.html
      def repack_pubkey(pubkey)
        p = pubkey.htb
        case p[0]
          when "\x06", "\x07"
            p[0] = "\x04"
            p
          else
            pubkey.htb
        end
      end

    end

  end
end
