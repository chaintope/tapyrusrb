require 'spec_helper'

describe Schnorr do

  describe 'end to end schnorr' do
    it 'should generate and verify' do
      key = Tapyrus::Key.generate
      private_key = key.priv_key.to_i(16)
      public_key = key.pubkey.htb
      msg = SecureRandom.bytes(32)

      signature = Schnorr.sign(msg, private_key).encode
      expect(Schnorr.valid_sig?(msg, signature, public_key)).to be true

      signature[SecureRandom.random_number(6)] = (1 + SecureRandom.random_number(255)).to_s(16).htb
      expect(Schnorr.valid_sig?(msg, signature, public_key)).to be false
    end
  end

  describe 'compact schnorr' do
    it 'should be passed.' do
      # Test Vector 1
      pubkey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'.htb
      message = '0000000000000000000000000000000000000000000000000000000000000000'.htb
      sig = '787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef67031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be true

      # Test vector 2
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be true

      # Test Vector 3
      pubkey = '03fac2114c2fbb091527eb7c64ecb11f8021cb45e8e7809d3c0938e4b8c0e5f84b'.htb
      message = '5e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c'.htb
      sig = '00da9b08172a9b6f0466a2defd817f2d7ab437e0d253cb5395a963866b3574be00880371d01766935b92d2ab4cd5c8a2a5837ec57fed7660773a05f0de142380'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be true

      # Test vector 4
      pubkey = '03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34'.htb
      message = '4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703'.htb
      sig = '00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6302a8dc32e64e86a333f20ef56eac9ba30b7246d6d25e22adb8c6be1aeb08d49d'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be true

      # Test vector 4b
      pubkey = '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'.htb
      message = '0000000000000000000000000000000000000000000000000000000000000000'.htb
      sig = '52818579aca59767e3291d91b76b637bef062083284992f2d95f564ca6cb4e3530b1da849c8e8304adc0cfe870660334b3cfc18e825ef1db34cfae3dfc5d8187'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be true

      # Test vector 6: R.y is not a quadratic residue
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1dfa16aee06609280a19b67a24e1977e4697712b5fd2943914ecd5f730901b4ab7'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 6
      pubkey = '03fac2114c2fbb091527eb7c64ecb11f8021cb45e8e7809d3c0938e4b8c0e5f84b'.htb
      message = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'.htb
      sig = '570dd4ca83d4e6317b8ee6bae83467a1bf419d0767122de409394414b05080dce9ee5f237cbd108eabae1e37759ae47f8e4203da3532eb28db860f33d62d49bd'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be true

      # Test vector 8
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1dfa16aee06609280a19b67a24e1977e4697712b5fd2943914ecd5f730901b4ab7'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 7: Negated message hash, R.x mismatch
      pubkey = '03fac2114c2fbb091527eb7c64ecb11f8021cb45e8e7809d3c0938e4b8c0e5f84b'.htb
      message = '5e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c'.htb
      sig = '00da9b08172a9b6f0466a2defd817f2d7ab437e0d253cb5395a963866b3574bed092f9d860f1776a1f7412ad8a1eb50daccc222bc8c0e26b2056df2f273efdec'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 8: Negated s, R.x mismatch
      pubkey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'.htb
      message = '0000000000000000000000000000000000000000000000000000000000000000'.htb
      sig = '787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef68fce5677ce7a623cb20011225797ce7a8de1dc6ccd4f754a47da6c600e59543c'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 9: Negated P, R.x mismatch
      pubkey = '03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 10: s * G = e * P, R = 0
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d8c3428869a663ed1e954705b020cbb3e7bb6ac31965b9ea4c73e227b17c5af5a'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 11: R.x not on the curve, R.x mismatch
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 12: r = p
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc2f1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false

      # Test vector 13: s = n
      pubkey = '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'.htb
      message = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'.htb
      sig = '2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1dfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'.htb
      expect(Schnorr.valid_sig?(message, sig, pubkey)).to be false
    end
  end

end