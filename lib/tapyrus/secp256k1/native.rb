# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

module Tapyrus
  module Secp256k1
    # binding for secp256k1 (https://github.com/chaintope/tapyrus-core/tree/v0.4.0/src/secp256k1)
    # tag: v0.4.0
    # this is not included by default, to enable set shared object path to ENV['SECP256K1_LIB_PATH']
    # for linux, ENV['SECP256K1_LIB_PATH'] = '/usr/local/lib/libsecp256k1.so'
    # for mac,
    module Native
      include ::FFI::Library
      extend self

      SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
      SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
      SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)

      SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
      SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
      SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

      # Flags to pass to secp256k1_context_create.
      SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
      SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)

      # Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export.
      SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
      SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)

      module_function

      def init
        raise 'secp256k1 library dose not found.' unless File.exist?(ENV['SECP256K1_LIB_PATH'])
        ffi_lib(ENV['SECP256K1_LIB_PATH'])
        load_functions
      end

      def load_functions
        attach_function(:secp256k1_context_create, [:uint], :pointer)
        attach_function(:secp256k1_context_destroy, [:pointer], :void)
        attach_function(:secp256k1_context_randomize, [:pointer, :pointer], :int)
        attach_function(:secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ec_seckey_verify, [:pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int)
        attach_function(:secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int)
        attach_function(:secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int)
        attach_function(:secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_schnorr_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_schnorr_verify, [:pointer, :pointer, :pointer, :pointer], :int)
      end

      def with_context(flags: (SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        init
        begin
          context = secp256k1_context_create(flags)
          ret, tries, max = 0, 0, 20
          while ret != 1
            raise 'secp256k1_context_randomize failed.' if tries >= max
            tries += 1
            ret = secp256k1_context_randomize(context, FFI::MemoryPointer.from_string(SecureRandom.random_bytes(32)))
          end
          yield(context) if block_given?
        ensure
          secp256k1_context_destroy(context)
        end
      end

      # generate ec private key and public key
      def generate_key_pair(compressed: true)
        with_context do |context|
          ret, tries, max = 0, 0, 20
          while ret != 1
            raise 'secp256k1_ec_seckey_verify in generate_key_pair failed.' if tries >= max
            tries += 1
            priv_key = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.random_bytes(32))
            ret = secp256k1_ec_seckey_verify(context, priv_key)
          end
          private_key = priv_key.read_string(32).bth
          [private_key, generate_pubkey_in_context(context, private_key, compressed: compressed)]
        end
      end

      # generate tapyrus key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Tapyrus::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      def generate_pubkey(priv_key, compressed: true)
        with_context { |context| generate_pubkey_in_context(context, priv_key, compressed: compressed) }
      end

      # sign data.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign
      # @param [String] extra_entropy a extra entropy for rfc6979
      # @return [String] signature data with binary format
      def sign_data(data, privkey, extra_entropy, algo: :ecdsa)
        case algo
        when :ecdsa
          sign_ecdsa(data, privkey, extra_entropy)
        when :schnorr
          sign_schnorr(data, privkey)
        else
          nil
        end
      end

      # verify signature.
      # @param[String] data a data.
      # @param [String] sig signature data with binary format
      # @param [String] pub_key a public key using verify.
      def verify_sig(data, sig, pub_key, algo: :ecdsa)
        case algo
        when :ecdsa
          verify_ecdsa(data, sig, pub_key)
        when :schnorr
          verify_schnorr(data, sig, pub_key)
        else
          false
        end
      end

      # # validate whether this is a valid public key (more expensive than IsValid())
      # @param [String] pub_key public key with hex format.
      # @param [Boolean] allow_hybrid whether support hybrid public key.
      # @return [Boolean] If valid public key return true, otherwise false.
      def parse_ec_pubkey?(pub_key, allow_hybrid = false)
        pub_key = pub_key.htb
        return false if !allow_hybrid && ![0x02, 0x03, 0x04].include?(pub_key[0].ord)
        with_context do |context|
          pubkey = FFI::MemoryPointer.new(:uchar, pub_key.bytesize).put_bytes(0, pub_key)
          internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pub_key.bytesize)
          result == 1
        end
      end

      private

      def generate_pubkey_in_context(context, privkey, compressed: true)
        internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
        result = secp256k1_ec_pubkey_create(context, internal_pubkey, privkey.htb)
        raise 'error creating pubkey' unless result

        pubkey = FFI::MemoryPointer.new(:uchar, 65)
        pubkey_len = FFI::MemoryPointer.new(:uint64)
        result =
          if compressed
            pubkey_len.put_uint64(0, 33)
            secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, internal_pubkey, SECP256K1_EC_COMPRESSED)
          else
            pubkey_len.put_uint64(0, 65)
            secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, internal_pubkey, SECP256K1_EC_UNCOMPRESSED)
          end
        raise 'error serialize pubkey' unless result || pubkey_len.read_uint64 > 0
        pubkey.read_string(pubkey_len.read_uint64).bth
      end

      def sign_ecdsa(data, privkey, extra_entropy)
        with_context do |context|
          secret = FFI::MemoryPointer.new(:uchar, privkey.htb.bytesize).put_bytes(0, privkey.htb)
          raise 'priv_key invalid' unless secp256k1_ec_seckey_verify(context, secret)

          internal_signature = FFI::MemoryPointer.new(:uchar, 64)
          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          entropy = extra_entropy ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, extra_entropy) : nil

          ret, tries, max = 0, 0, 20

          while ret != 1
            raise 'secp256k1_ecdsa_sign failed.' if tries >= max
            tries += 1
            ret = secp256k1_ecdsa_sign(context, internal_signature, msg32, secret, nil, entropy)
          end

          signature = FFI::MemoryPointer.new(:uchar, 72)
          signature_len = FFI::MemoryPointer.new(:uint64).put_uint64(0, 72)
          result = secp256k1_ecdsa_signature_serialize_der(context, signature, signature_len, internal_signature)
          raise 'secp256k1_ecdsa_signature_serialize_der failed' unless result

          signature.read_string(signature_len.read_uint64)
        end
      end

      def sign_schnorr(data, privkey)
        with_context do |context|
          secret = FFI::MemoryPointer.new(:uchar, privkey.htb.bytesize).put_bytes(0, privkey.htb)
          raise 'priv_key invalid' unless secp256k1_ec_seckey_verify(context, secret)

          signature = FFI::MemoryPointer.new(:uchar, 64)
          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          unless secp256k1_schnorr_sign(context, signature, msg32, secret, nil, nil) == 1
            raise 'Failed to generate schnorr signature.'
          end
          signature.read_string(64)
        end
      end

      def verify_ecdsa(data, sig, pub_key)
        with_context do |context|
          return false if data.bytesize == 0

          pubkey = FFI::MemoryPointer.new(:uchar, pub_key.htb.bytesize).put_bytes(0, pub_key.htb)
          internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey.size)
          return false unless result

          signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
          internal_signature = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ecdsa_signature_parse_der(context, internal_signature, signature, signature.size)
          return false unless result

          # libsecp256k1's ECDSA verification requires lower-S signatures, which have not historically been enforced in Bitcoin, so normalize them first.
          secp256k1_ecdsa_signature_normalize(context, internal_signature, internal_signature)

          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          result = secp256k1_ecdsa_verify(context, internal_signature, msg32, internal_pubkey)

          result == 1
        end
      end

      def verify_schnorr(data, sig, pub_key)
        with_context do |context|
          return false if data.bytesize == 0
          pubkey = FFI::MemoryPointer.new(:uchar, pub_key.htb.bytesize).put_bytes(0, pub_key.htb)
          internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey.size)
          return false unless result

          signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)

          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          result = secp256k1_schnorr_verify(context, signature, msg32, internal_pubkey)

          result == 1
        end
      end
    end
  end
end
