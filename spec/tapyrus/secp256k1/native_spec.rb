require 'spec_helper'

describe Tapyrus::Secp256k1::Native, use_secp256k1: true do
  describe '#generate_key_pair' do
    context 'compressed' do
      subject { Tapyrus::Secp256k1::Native.generate_key_pair }
      it 'should be generate' do
        expect(subject.length).to eq(2)

        # privkey
        expect(subject[0].htb.bytesize).to eq(32)

        # pubkey
        expect(subject[1].htb.bytesize).to eq(33)
        expect(['02', '03'].include?(subject[1].htb[0].bth)).to be true
      end
    end

    context 'uncompressed' do
      subject { Tapyrus::Secp256k1::Native.generate_key_pair(compressed: false) }
      it 'should be generate' do
        expect(subject.length).to eq(2)

        # privkey
        expect(subject[0].htb.bytesize).to eq(32)

        # pubkey
        expect(subject[1].htb.bytesize).to eq(65)
        expect(subject[1].htb[0].bth).to eq('04')
      end
    end
  end

  describe '#generate_key' do
    context 'compressed' do
      subject { Tapyrus::Secp256k1::Native.generate_key }
      it 'should be generate' do
        expect(subject.compressed?).to be true
      end
    end

    context 'uncompressed' do
      subject { Tapyrus::Secp256k1::Native.generate_key(compressed: false) }
      it 'should be generate' do
        expect(subject.compressed?).to be false
      end
    end
  end

  describe '#generate_pubkey' do
    subject { Tapyrus::Secp256k1::Native.generate_pubkey(privkey, compressed: true) }

    let(:privkey) { '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff' }

    it { is_expected.to eq '020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a' }
  end

  describe '#sign_data/#verify_data' do
    it 'should be signed' do
      message = 'message'
      priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
      pub_key = '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'
      sig = Tapyrus::Secp256k1::Native.sign_data(message, priv_key, nil)
      expect(Tapyrus::Secp256k1::Native.verify_sig(message, sig, pub_key)).to be true
      expect(Tapyrus::Secp256k1::Native.verify_sig('hoge', sig, pub_key)).to be false
    end
  end
end
