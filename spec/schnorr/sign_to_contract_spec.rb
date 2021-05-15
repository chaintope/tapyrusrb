require 'spec_helper'

describe 'Schnorr::SignToContract' do
  let(:contract) { Tapyrus.sha256('foo') }
  let(:message) { 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'.htb }
  let(:key) { Tapyrus::Key.from_wif('cW2r6zzDwqmxhKiRckCnpXmPB25csqUUkJyJ2Jab71pLa2J1HVTv') }
  let(:private_key) { key.priv_key.to_i(16) }
  let(:public_key) { key.pubkey.htb }

  describe '.sign' do
    subject do
      signature, r = Schnorr::SignToContract.sign(message, private_key, contract)
      Schnorr.valid_sig?(message, signature.encode, public_key)
    end

    it { is_expected.to be_truthy }
  end

  describe '.valid_contract?' do
    subject do
      signature, r = Schnorr::SignToContract.sign(message, private_key, contract)
      Schnorr::SignToContract.valid_contract?(r, signature, test)
    end

    context 'valid contract' do
      let(:test) { Tapyrus.sha256('foo') }
      it { is_expected.to be_truthy }
    end

    context 'invalid contract' do
      let(:test) { Tapyrus.sha256('bar') }
      it { is_expected.to be_falsy }
    end
  end
end
