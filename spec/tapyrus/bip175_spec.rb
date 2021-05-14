require 'spec_helper'

describe 'Tapyrus::BIP175' do
  before { Tapyrus.chain_params = :prod }

  let(:master) do
    Tapyrus::ExtKey.from_base58(
      'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73'
    )
  end
  let(:payment_base) do
    Tapyrus::ExtPubkey.from_base58(
      'xpub6B3JSEWjqm5GgfzcjPwBixxLPzi15pFM3jq4E4yCzXXUFS5MFdXiSdw7b5dbdPGHuc7c1V4zXbbFRtc9G1njMUt9ZvMdGVGYQSQsurD6HAW'
    )
  end

  let(:document1) { 'foo' }
  let(:document2) { 'bar' }

  # contract base public extended key:
  describe '.from_private_key' do
    subject { key.payment_base.to_base58 }

    let(:key) { Tapyrus::BIP175.from_ext_key(master) }

    it do
      is_expected.to eq 'xpub6B3JSEWjqm5GgfzcjPwBixxLPzi15pFM3jq4E4yCzXXUFS5MFdXiSdw7b5dbdPGHuc7c1V4zXbbFRtc9G1njMUt9ZvMdGVGYQSQsurD6HAW'
    end
  end

  describe '.from_public_key' do
    subject { key.payment_base.to_base58 }

    let(:key) { Tapyrus::BIP175.from_ext_pubkey(payment_base) }

    it do
      is_expected.to eq 'xpub6B3JSEWjqm5GgfzcjPwBixxLPzi15pFM3jq4E4yCzXXUFS5MFdXiSdw7b5dbdPGHuc7c1V4zXbbFRtc9G1njMUt9ZvMdGVGYQSQsurD6HAW'
    end
  end

  describe '#combined_hash' do
    subject { key.combined_hash.bth }

    before do
      key << document1
      key << document2
    end
    let(:key) { Tapyrus::BIP175.from_ext_key(master) }

    it { is_expected.to eq '310057788c6073640dc222466d003411cd5c1cc0bf2803fc6ebbfae03ceb4451' }
  end

  describe '#addr' do
    subject { key.addr }

    before do
      key << document1
      key << document2
    end
    let(:key) { Tapyrus::BIP175.from_ext_key(master) }

    it { is_expected.to eq '1C7f322izqMqLzZzfzkPAjxBzprxDi47Yf' }
  end
end
