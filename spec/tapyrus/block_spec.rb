require 'spec_helper'

describe Tapyrus::Block do

  subject {
    payload = load_block('896574bee055370c047e911212f8472e7e77a1337d666e2a83da739d04f8de2a').htb
    Tapyrus::Message::Block.parse_from_payload(payload).to_block
  }

  describe '#valid_merkle_root?' do
    context 'valid' do
      it 'should be true' do
        expect(subject.valid_merkle_root?).to be true
      end
    end

    context 'block has two transactions.' do
      subject {
        payload = load_block('75be7b3b19e07f2c3644523016132db7e7e67063b3f5abbaa420cafc8a44557f').htb
        Tapyrus::Message::Block.parse_from_payload(payload).to_block
      }
      it 'should be true' do
        expect(subject.valid_merkle_root?).to be true
      end
    end

    context 'invalid' do
      it 'should be false' do
        block = subject
        coinbase_tx = block.transactions[0]
        coinbase_tx.inputs[0].script_sig = (coinbase_tx.inputs[0].script_sig << '00')
        expect(subject.valid_merkle_root?).to be false
      end
    end
  end

  describe '#height' do
    it 'stored in coinbase tx.' do
      expect(subject.height).to eq(18870)
    end
  end

end