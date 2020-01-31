module Tapyrus
  module Secp256k1
    module RFC6979

      INITIAL_V = '0101010101010101010101010101010101010101010101010101010101010101'.htb
      INITIAL_K = '0000000000000000000000000000000000000000000000000000000000000000'.htb
      ZERO_B = '00'.htb
      ONE_B = '01'.htb

      module_function

      # generate temporary key k to be used when ECDSA sign.
      # https://tools.ietf.org/html/rfc6979#section-3.2
      # @param [String] data a data to be signed with binary format.
      # @param [String] privkey a private key using sign with binary format.
      # @param [String] extra_entropy extra entropy with binary format.
      # @return [Integer] a nonce.
      def generate_rfc6979_nonce(data, privkey, extra_entropy)
        v = INITIAL_V # 3.2.b
        k = INITIAL_K # 3.2.c
        # 3.2.d
        k = Tapyrus.hmac_sha256(k, v + ZERO_B + privkey + data + extra_entropy)
        # 3.2.e
        v = Tapyrus.hmac_sha256(k, v)
        # 3.2.f
        k = Tapyrus.hmac_sha256(k, v + ONE_B + privkey + data + extra_entropy)
        # 3.2.g
        v = Tapyrus.hmac_sha256(k, v)
        # 3.2.h
        t = ''
        10000.times do
          v = Tapyrus.hmac_sha256(k, v)
          t = (t + v)
          t_num = t.bth.to_i(16)
          return t_num if 1 <= t_num && t_num < Tapyrus::Secp256k1::GROUP.order
          k = Tapyrus.hmac_sha256(k, v + '00'.htb)
          v = Tapyrus.hmac_sha256(k, v)
        end
        raise 'A valid nonce was not found.'
      end

    end
  end
end