require 'spec_helper'

describe Tapyrus::Key do
  describe '#from_wif' do
    context 'mainnet', network: :prod do
      subject { Tapyrus::Key.from_wif('KxJkzWsRQmr2bdU9TdWDFhXxg9nsELSEQojEQFZMFqJsHTBSXpP9') }
      it 'should be parse' do
        expect(subject.priv_key).to eq('206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff')
        expect(subject.pubkey).to eq('020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a')
        expect(subject.to_p2pkh).to eq('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')
      end
    end

    context 'testnet', network: :dev do
      subject { Tapyrus::Key.from_wif('cPaJYBMDLjQp5gSUHnBfhX4Rgj95ekBS6oBttwQLw3qfsKKcDfuB') }
      it 'should be parse' do
        expect(subject.compressed?).to be true
        expect(subject.priv_key).to eq('3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438')
        expect(subject.pubkey).to eq('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')
        expect(subject.to_p2pkh).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      end
    end
  end

  describe '#to_wif' do
    context 'mainnet', network: :prod do
      subject { Tapyrus::Key.new(priv_key: '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff').to_wif }
      it 'should be export' do
        expect(subject).to eq('KxJkzWsRQmr2bdU9TdWDFhXxg9nsELSEQojEQFZMFqJsHTBSXpP9')
      end
    end
    context 'testnet' do
      subject { Tapyrus::Key.new(priv_key: '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438').to_wif }
      it 'should be export' do
        expect(subject).to eq('cPaJYBMDLjQp5gSUHnBfhX4Rgj95ekBS6oBttwQLw3qfsKKcDfuB')
      end
    end
  end

  describe '#compress_or_uncompress_pubkey?' do
    it 'should be checked' do
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0'
        )
      ).to be true
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '030efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47'
        )
      ).to be true
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '04a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313'
        )
      ).to be true
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '02a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313'
        )
      ).to be false
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '03a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313'
        )
      ).to be false
      expect(Tapyrus::Key.compress_or_uncompress_pubkey?('')).to be false
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '000efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47'
        )
      ).to be false
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '040efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47'
        )
      ).to be false
    end
  end

  describe '#compress_pubkey?' do
    it 'should be checked' do
      expect(
        Tapyrus::Key.compress_pubkey?('02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0')
      ).to be true
      expect(
        Tapyrus::Key.compress_pubkey?('030efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47')
      ).to be true
      expect(
        Tapyrus::Key.compress_pubkey?(
          '04a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313'
        )
      ).to be false
      expect(Tapyrus::Key.compress_or_uncompress_pubkey?('')).to be false
      expect(
        Tapyrus::Key.compress_or_uncompress_pubkey?(
          '040efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47'
        )
      ).to be false
    end
  end

  describe '#to_point' do
    context 'compress pubkey' do
      subject do
        Tapyrus::Key.new(pubkey: '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9').to_point
      end
      it 'should be generate ec point' do
        expect(subject.x).to eq(
          66_459_088_590_212_380_792_611_386_255_453_021_887_227_364_243_207_655_103_300_857_960_258_170_950_345
        )
        expect(subject.y).to eq(
          35_473_366_296_081_526_532_737_740_169_602_173_612_426_578_347_181_408_584_726_802_824_997_634_845_606
        )
        expect(subject.group).to eq(Tapyrus::Secp256k1::GROUP)
      end
    end

    context 'uncompress pubkey' do
      subject do
        Tapyrus::Key.new(
          pubkey:
            '0492ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c94e6d36bc82983001902d48cb877671a4f50b40aa5d794ebdea1bdf76e36c2ba6',
          compressed: false
        ).to_point
      end
      it 'should be generate ec point' do
        expect(subject.x).to eq(
          66_459_088_590_212_380_792_611_386_255_453_021_887_227_364_243_207_655_103_300_857_960_258_170_950_345
        )
        expect(subject.y).to eq(
          35_473_366_296_081_526_532_737_740_169_602_173_612_426_578_347_181_408_584_726_802_824_997_634_845_606
        )
        expect(subject.group).to eq(Tapyrus::Secp256k1::GROUP)
      end
    end
  end

  describe '#sign and verify' do
    context 'use ruby native code' do
      it 'should be success' do
        sign_verify
      end
    end

    context 'use libsecp256k1', use_secp256k1: true do
      it 'should be success' do
        sign_verify
      end
    end
  end

  def sign_verify
    message = Tapyrus.sha256('message'.htb)
    key = Tapyrus::Key.new(priv_key: '78999378da075ab0583873df5f2cb498f07682e5c0c92fe2d256eecdc1af133b')

    # ecdsa
    sig = key.sign(message)
    expect(key.verify(sig, message)).to be true
    expect(key.verify(sig, message, algo: :schnorr)).to be false

    # schnorr
    sig = key.sign(message, algo: :schnorr)
    expect(key.verify(sig, message)).to be false
    expect(key.verify(sig, message, algo: :schnorr)).to be true
  end

  describe 'private key range check' do
    context 'on curve' do
      it 'not raise error' do
        expect { Tapyrus::Key.new(priv_key: '01') }.not_to raise_error
        expect {
          Tapyrus::Key.new(priv_key: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140')
        }.not_to raise_error
        expect(
          Tapyrus::Key.new(priv_key: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140')
            .fully_valid_pubkey?
        ).to be true
      end
    end

    context 'not on curve' do
      it 'raise error' do
        expect { Tapyrus::Key.new(priv_key: '00') }.to raise_error(ArgumentError)
        expect {
          Tapyrus::Key.new(priv_key: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe 'low/high R signature', network: :prod do
    context 'same sig output as Tapyrus Core' do
      it 'should be generate' do
        key = Tapyrus::Key.from_wif('5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf')
        tx =
          Tapyrus::Tx.parse_from_payload(
            '01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d0000000000ffffffff01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00000000'
              .htb
          )
        tmp = tx.out.pop
        script = Tapyrus::Script.parse_from_payload('76a91491b24bf9f5288532960ac687abb035127b1d28a588ac'.htb)
        sighash = tx.sighash_for_input(0, script)
        sig = key.sign(sighash) + [Tapyrus::SIGHASH_TYPE[:all]].pack('C')
        expect(sig.bth).to eq(
          '30440220131432090a6af42da3e8335ff110831b41a44f4e9d18d88f5d50278380696c7202200fc2e48938f323ad13625890c0ea926c8a189c08b8efc38376b20c8a2188e96e01'
        )
        tx.in[0].script_sig = Tapyrus::Script.new << sig << key.pubkey.htb
        tx.out[0] = tmp
        expect(tx.to_hex).to eq(
          '01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d000000008a4730440220131432090a6af42da3e8335ff110831b41a44f4e9d18d88f5d50278380696c7202200fc2e48938f323ad13625890c0ea926c8a189c08b8efc38376b20c8a2188e96e01410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ffffffff01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00000000'
        )
      end
    end

    let(:key) { Tapyrus::Key.from_wif('5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj') }

    context 'entropy is specified' do
      it 'should see at least one high R signature within 20 signatures' do
        test_with_entropy
      end
    end

    context 'entropy is not specified' do
      it 'should always see low R signatures that are less than 70 bytes in 256 tries' do
        test_with_no_entropy
      end
    end

    context 'entropy is specified with libsecp256k1', use_secp256k1: true do
      it 'should see at least one high R signature within 20 signatures' do
        test_with_entropy
      end
    end

    context 'entropy is not specified with libsecp256k1', use_secp256k1: true do
      it 'should always see low R signatures that are less than 70 bytes in 256 tries' do
        test_with_no_entropy
      end
    end

    def test_with_entropy
      hash = Tapyrus.double_sha256('A message to be signed')
      found = false
      (1..20).each do |i|
        tmp = [i].pack('I*').bth
        entropy = tmp.ljust(64, '0').htb
        sig = key.sign(hash, false, entropy)
        found = (sig[3].bth.to_i(16) == 0x21 && sig[4].bth.to_i(16) == 0x00)
        expect(sig.bth).to eq(
          '304502210089e94fcb5a449e0f230a0dfc3b97f3947d36f0030fc6f11e2bedc37e8ccb7fbc022073b7a71756273955ed3bbab4b818a537658160b7f08b5a82169ea9cb8ff96fdd'
        )
        break if found
      end
      expect(found).to be true
    end

    def test_with_no_entropy
      found = true
      found_small = false
      256.times do |i|
        hash = Tapyrus.double_sha256("A message to be signed#{i}")
        sig = key.sign(hash)
        found = (sig[3].bth.to_i(16) == 0x20)
        expect(sig.size <= 70).to be true
        found_small |= sig.bytesize <= 70
      end
      expect(found).to be true
      expect(found_small).to be true
    end
  end
end
